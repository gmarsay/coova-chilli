/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * main-dhcp.c — Point d'entrée du processus chilli_dhcp
 *
 * chilli_dhcp est le seul propriétaire des raw sockets L2, de la table
 * DHCP et du pool IP. Il communique avec chilli (main) via une socket
 * Unix DGRAM (voir dhcpipc.h).
 *
 * Lancement : chilli_dhcp -b <binconfig>
 */

#define MAIN_FILE

#include "chilli.h"
#include "dhcpipc.h"
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>

struct options_t _options;

/* ------------------------------------------------------------------ */
/* Table locale des clients DHCP (indexée par MAC)                      */
/* ------------------------------------------------------------------ */

#define DHCP_LOCAL_MAX 4096

struct dhcp_local_client {
  uint8_t  inuse;
  uint8_t  mac[PKT_ETH_ALEN];
  uint32_t ip;
  uint8_t  authstate;  /* DHCP_AUTH_* */
  uint16_t vlan;
};

static struct dhcp_local_client local_clients[DHCP_LOCAL_MAX];

static struct dhcp_local_client *local_client_find(const uint8_t *mac) {
  int i;
  for (i = 0; i < DHCP_LOCAL_MAX; i++) {
    if (local_clients[i].inuse &&
        memcmp(local_clients[i].mac, mac, PKT_ETH_ALEN) == 0)
      return &local_clients[i];
  }
  return NULL;
}

static struct dhcp_local_client *local_client_alloc(const uint8_t *mac,
                                                    uint32_t ip,
                                                    uint16_t vlan) {
  int i;
  for (i = 0; i < DHCP_LOCAL_MAX; i++) {
    if (!local_clients[i].inuse) {
      memset(&local_clients[i], 0, sizeof(local_clients[i]));
      local_clients[i].inuse     = 1;
      memcpy(local_clients[i].mac, mac, PKT_ETH_ALEN);
      local_clients[i].ip        = ip;
      local_clients[i].vlan      = vlan;
      local_clients[i].authstate = DHCP_AUTH_NONE;
      return &local_clients[i];
    }
  }
  return NULL;
}

static void local_client_free(const uint8_t *mac) {
  struct dhcp_local_client *c = local_client_find(mac);
  if (c) c->inuse = 0;
}

/* ------------------------------------------------------------------ */
/* État global                                                           */
/* ------------------------------------------------------------------ */

static struct dhcp_t   *dhcp_g    = NULL;
static struct ippool_t *ippool_g  = NULL;

static int  ipc_srv_fd  = -1;   /* serveur : reçoit SET_AUTHSTATE / KICK */
static int  ipc_cli_fd  = -1;   /* client  : envoie NEW_CLIENT / GONE     */
static char ipc_main_path[108];  /* chemin du socket côté main             */
static char ipc_srv_path[108];   /* chemin du socket de ce processus       */

static volatile int keep_going    = 1;
static volatile int reload_config = 0;

/* ------------------------------------------------------------------ */
/* Callbacks DHCP internes                                              */
/* ------------------------------------------------------------------ */

static int cb_local_dhcp_connect(struct dhcp_conn_t *conn) {
  struct dhcp_local_client *lc;

  lc = local_client_find(conn->hismac);
  if (!lc)
    lc = local_client_alloc(conn->hismac, conn->hisip.s_addr, 0);

  if (!lc) {
    syslog(LOG_ERR, "chilli_dhcp: local client table full!");
    return -1;
  }

  syslog(LOG_INFO, "chilli_dhcp: new client MAC="MAC_FMT" IP=%s",
         MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));

  if (ipc_cli_fd >= 0)
    dhcpipc_send_new_client(ipc_cli_fd, ipc_main_path,
                            conn->hismac, conn->hisip.s_addr, lc->vlan);
  return 0;
}

static int cb_local_dhcp_disconnect(struct dhcp_conn_t *conn, int term_cause) {
  dhcpipc_gone_reason_t reason;

  switch (term_cause) {
    case RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT:
    case RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT:
      reason = DHCPIPC_GONE_TIMEOUT;
      break;
    default:
      reason = DHCPIPC_GONE_RELEASE;
      break;
  }

  syslog(LOG_INFO, "chilli_dhcp: client gone MAC="MAC_FMT" IP=%s",
         MAC_ARG(conn->hismac), inet_ntoa(conn->hisip));

  if (ipc_cli_fd >= 0)
    dhcpipc_send_client_gone(ipc_cli_fd, ipc_main_path,
                             conn->hismac, conn->hisip.s_addr, reason);

  local_client_free(conn->hismac);
  return 0;
}

static int cb_local_dhcp_request(struct dhcp_conn_t *conn,
                                  struct in_addr *addr,
                                  uint8_t *dhcp_pkt, size_t dhcp_len) {
  struct ippoolm_t *ipm = NULL;
  (void)dhcp_pkt; (void)dhcp_len;

  if (conn->hisip.s_addr)
    return 0;  /* IP déjà allouée */

  if (ippool_newip(ippool_g, &ipm, addr, 1)) {
    if (ippool_newip(ippool_g, &ipm, addr, 0)) {
      syslog(LOG_ERR, "chilli_dhcp: ippool_newip failed for %s",
             addr ? inet_ntoa(*addr) : "any");
      return -1;
    }
  }

  conn->hisip = ipm->addr;
  conn->ourip = dhcp_g->ourip;
  return 0;
}

static int cb_local_dhcp_data_ind(struct dhcp_conn_t *conn,
                                   uint8_t *pack, size_t len) {
  /* Dans l'architecture chilli_dhcp, le filtrage est fait par nftables.
     On ne fait rien de spécial ici pour l'instant. */
  (void)conn; (void)pack; (void)len;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Callback IPC (enregistré dans le select loop via net_select_reg)     */
/* ------------------------------------------------------------------ */

static int ipc_select_cb(void *data, int idx) {
  struct dhcpipc_msg msg;
  struct dhcp_local_client *lc;
  uint8_t mac[PKT_ETH_ALEN];
  (void)data; (void)idx;

  if (dhcpipc_recv(ipc_srv_fd, &msg, NULL) != 0)
    return -1;

  memcpy(mac, msg.mac, PKT_ETH_ALEN);

  switch ((dhcpipc_type_t)msg.type) {

    case DHCPIPC_SET_AUTHSTATE:
      lc = local_client_find(mac);
      if (lc) {
        lc->authstate = msg.authstate;
        syslog(LOG_DEBUG,
               "chilli_dhcp: SET_AUTHSTATE MAC="MAC_FMT" state=%d",
               MAC_ARG(mac), msg.authstate);
        if (dhcp_g) {
          struct dhcp_conn_t *conn = NULL;
          if (dhcp_hashget(dhcp_g, &conn, mac) == 0 && conn)
            conn->authstate = msg.authstate;
        }
      }
      break;

    case DHCPIPC_KICK_CLIENT:
      syslog(LOG_INFO, "chilli_dhcp: KICK MAC="MAC_FMT, MAC_ARG(mac));
      if (dhcp_g) {
        struct dhcp_conn_t *conn = NULL;
        if (dhcp_hashget(dhcp_g, &conn, mac) == 0 && conn)
          dhcp_freeconn(conn, RADIUS_TERMINATE_CAUSE_ADMIN_RESET);
          /* cb_local_dhcp_disconnect envoie CLIENT_GONE au main */
      }
      break;

    default:
      syslog(LOG_WARNING, "chilli_dhcp: unknown IPC type %d", msg.type);
      break;
  }

  return 0;
}

/* ------------------------------------------------------------------ */
/* Gestion signaux                                                       */
/* ------------------------------------------------------------------ */

static void sig_handler(int signum) {
  if (signum == SIGTERM || signum == SIGINT)
    keep_going = 0;
  else if (signum == SIGHUP || signum == SIGUSR1)
    reload_config = 1;
}

/* ------------------------------------------------------------------ */
/* main()                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
  int i;
  select_ctx sctx;
  const char *base_path;

  openlog("chilli_dhcp", LOG_PID, LOG_DAEMON);

  /* 1 — Charger la configuration via -b <binconfig> */
  if (!process_options(argc, argv, 0)) {
    syslog(LOG_ERR, "chilli_dhcp: failed to load options");
    return 1;
  }

  /* 2 — Signaux */
  signal(SIGTERM, sig_handler);
  signal(SIGINT,  sig_handler);
  signal(SIGHUP,  sig_handler);
  signal(SIGUSR1, sig_handler);
  signal(SIGPIPE, SIG_IGN);

  /* 3 — Pool IP */
  if (ippool_new(&ippool_g,
                 _options.dynip,
                 _options.dhcpstart,
                 _options.dhcpend,
                 _options.statip,
                 _options.allowdyn,
                 _options.allowstat)) {
    syslog(LOG_ERR, "chilli_dhcp: ippool_new failed");
    return 1;
  }

  /* 4 — Instance DHCP */
  if (dhcp_new(&dhcp_g,
               _options.max_clients,
               _options.dhcphashsize,
               _options.dhcpif,
               _options.dhcpusemac,
               _options.dhcpmac, 1,
               &_options.dhcplisten, _options.lease, 1,
               &_options.uamlisten, _options.uamport,
               _options.noc2c)) {
    syslog(LOG_ERR, "chilli_dhcp: dhcp_new failed on %s", _options.dhcpif);
    return 1;
  }

  dhcp_set_cb_connect(dhcp_g,    cb_local_dhcp_connect);
  dhcp_set_cb_disconnect(dhcp_g, cb_local_dhcp_disconnect);
  dhcp_set_cb_request(dhcp_g,    cb_local_dhcp_request);
  dhcp_set_cb_data_ind(dhcp_g,   cb_local_dhcp_data_ind);

  if (dhcp_set(dhcp_g, _options.ethers, (_options.debug & DEBUG_DHCP))) {
    syslog(LOG_ERR, "chilli_dhcp: dhcp_set failed");
    return 1;
  }

  /* 5 — Sockets IPC */
  base_path = (_options.dhcpsocket && *_options.dhcpsocket)
              ? _options.dhcpsocket
              : DHCPIPC_DEFAULT_SOCK;

  /* Chemin du socket côté main (on envoie là-dedans) */
  snprintf(ipc_main_path, sizeof(ipc_main_path), "%s", base_path);
  /* Chemin du socket propre à chilli_dhcp */
  snprintf(ipc_srv_path,  sizeof(ipc_srv_path),  "%s.d", base_path);

  ipc_srv_fd = dhcpipc_open_server(ipc_srv_path);
  if (ipc_srv_fd < 0) {
    syslog(LOG_ERR, "chilli_dhcp: cannot open IPC server %s", ipc_srv_path);
    return 1;
  }

  ipc_cli_fd = dhcpipc_open_client(ipc_main_path);
  if (ipc_cli_fd < 0) {
    syslog(LOG_ERR, "chilli_dhcp: cannot open IPC client");
    return 1;
  }

  syslog(LOG_INFO, "chilli_dhcp: started, IPC at %s", ipc_srv_path);

  /* 6 — Boucle select() */
  memset(&sctx, 0, sizeof(sctx));
  if (net_select_init(&sctx))
    syslog(LOG_ERR, "chilli_dhcp: net_select_init failed");

  /* Fds DHCP */
#if defined(__linux__)
  if (dhcp_g->relayfd > 0)
    net_select_reg(&sctx, dhcp_g->relayfd, SELECT_READ,
                   (select_callback)dhcp_relay_decaps, dhcp_g, 0);

  for (i = 0; i < MAX_RAWIF && dhcp_g->rawif[i].fd > 0; i++) {
    net_select_reg(&sctx, dhcp_g->rawif[i].fd, SELECT_READ,
                   (select_callback)dhcp_decaps, dhcp_g, i);
    dhcp_g->rawif[i].sctx = &sctx;
  }

#ifdef HAVE_NETFILTER_QUEUE
  if (dhcp_g->qif_in.fd && dhcp_g->qif_out.fd) {
    net_select_reg(&sctx, dhcp_g->qif_in.fd, SELECT_READ,
                   (select_callback)dhcp_decaps, dhcp_g, 1);
    net_select_reg(&sctx, dhcp_g->qif_out.fd, SELECT_READ,
                   (select_callback)dhcp_decaps, dhcp_g, 2);
  }
#endif

#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
  for (i = 0; i < MAX_RAWIF && dhcp_g->rawif[i].fd > 0; i++) {
    net_select_reg(&sctx, dhcp_g->rawif[i].fd, SELECT_READ,
                   (select_callback)dhcp_receive, dhcp_g, i);
  }
#endif

  /* Fd IPC avec son callback */
  net_select_reg(&sctx, ipc_srv_fd, SELECT_READ,
                 (select_callback)ipc_select_cb, NULL, 0);

  mainclock_tick();

  while (keep_going) {
    int status;
    time_t now;

    if (reload_config) {
      reload_config = 0;
      dhcp_set(dhcp_g, _options.ethers, (_options.debug & DEBUG_DHCP));
      syslog(LOG_INFO, "chilli_dhcp: configuration reloaded");
    }

    now = mainclock_now();

    /* dhcp_timeout() une fois par seconde */
    dhcp_timeout(dhcp_g);

    if (net_select_prepare(&sctx))
      syslog(LOG_ERR, "chilli_dhcp: net_select_prepare failed");

    status = net_select(&sctx);  /* timeout interne 1s */
    mainclock_tick();

    if (status > 0)
      net_run_selected(&sctx, status);

    (void)now;
  }

  syslog(LOG_INFO, "chilli_dhcp: shutting down");

  unlink(ipc_srv_path);
  if (ipc_srv_fd >= 0) close(ipc_srv_fd);
  if (ipc_cli_fd >= 0) close(ipc_cli_fd);

  return 0;
}

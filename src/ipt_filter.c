/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * ipt_filter.c — Filtrage kernel via iptables-legacy + ipset
 *
 * Crée un ipset "chilli_authed" (hash:ip, timeout 1h) et deux règles
 * FORWARD qui acceptent le trafic des clients authentifiés.
 *
 * Dépendances système : iptables-legacy, ipset (xt_set kmod).
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "ipt_filter.h"

#define IPSET_NAME "chilli_authed"
#define IPTABLES   "iptables-legacy"

/* Interface DHCP, uamlisten, uamport et uamuiport mémorisés pour le cleanup */
static char     _iface[64];
static char     _uamlisten[INET_ADDRSTRLEN];
static uint16_t _uamport;
static uint16_t _uamuiport;

/* ------------------------------------------------------------------ */
/* Helper : exécute une commande, retourne 0 si succès                  */
/* ------------------------------------------------------------------ */

static int run_cmd(const char *cmd) {
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    syslog(LOG_ERR, "ipt_filter: popen(\"%s\") failed", cmd);
    return -1;
  }
  int rc = pclose(fp);
  if (rc != 0)
    syslog(LOG_DEBUG, "ipt_filter: command returned %d: %s", rc, cmd);
  return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* API publique                                                          */
/* ------------------------------------------------------------------ */

int ipt_filter_init(const char *iface, struct in_addr uamlisten,
                    uint16_t uamport, uint16_t uamuiport) {
  char cmd[512];

  strncpy(_iface, iface ? iface : "", sizeof(_iface) - 1);
  _iface[sizeof(_iface) - 1] = '\0';
  if (!inet_ntop(AF_INET, &uamlisten, _uamlisten, sizeof(_uamlisten))) {
    syslog(LOG_ERR, "ipt_filter_init: inet_ntop(uamlisten) failed");
    return -1;
  }
  _uamport   = uamport;
  _uamuiport = uamuiport;

  /* Nettoyage d'une configuration précédente (ignore les erreurs) */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s"
           " -m set --match-set " IPSET_NAME " src -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s"
           " -m set --match-set " IPSET_NAME " dst -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);

  /* Nettoyage DNAT/REDIRECT NAT précédents (tolérant aux deux formes) */
  if (uamport) {
    int https_port_cleanup = (uamuiport > 0) ? uamuiport : uamport;
    /* Anciennes règles REDIRECT (rétrocompatibilité) */
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 80 -j REDIRECT --to-port %d 2>/dev/null",
             _iface, uamport);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 443 -j REDIRECT --to-port %d 2>/dev/null",
             _iface, https_port_cleanup);
    run_cmd(cmd);
    /* Règles DNAT actuelles */
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 80 -j DNAT --to-destination %s:%d 2>/dev/null",
             _iface, _uamlisten, uamport);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 443 -j DNAT --to-destination %s:%d 2>/dev/null",
             _iface, _uamlisten, https_port_cleanup);
    run_cmd(cmd);
  }

  /* Nettoyage DROP FORWARD précédents */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");

  /* Crée le set (hash:ip, timeout 1h) */
  if (run_cmd("ipset create " IPSET_NAME
              " hash:ip hashsize 1024 maxelem 65536 timeout 3600") != 0) {
    syslog(LOG_ERR, "ipt_filter_init: ipset create failed");
    return -1;
  }

  /* Règle src : trafic émis par un client authentifié — ACCEPT avant les DROP */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -i %s"
           " -m set --match-set " IPSET_NAME " src -j ACCEPT",
           _iface);
  if (run_cmd(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: iptables src rule failed");
    run_cmd("ipset destroy " IPSET_NAME);
    return -1;
  }

  /* Règle dst : trafic à destination d'un client authentifié */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -o %s"
           " -m set --match-set " IPSET_NAME " dst -j ACCEPT",
           _iface);
  if (run_cmd(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: iptables dst rule failed");
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -D FORWARD -i %s"
             " -m set --match-set " IPSET_NAME " src -j ACCEPT",
             _iface);
    run_cmd(cmd);
    run_cmd("ipset destroy " IPSET_NAME);
    return -1;
  }

  /* DROP : bloquer tout trafic FORWARD non-authentifié depuis/vers dhcpif */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A FORWARD -i %s -j DROP", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A FORWARD -o %s -j DROP", _iface);
  run_cmd(cmd);

  /* DNAT : HTTP → uamlisten:uamport, HTTPS → uamlisten:uamuiport (ou uamport) */
  if (uamport) {
    int https_port = (uamuiport > 0) ? uamuiport : uamport;

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -I PREROUTING 1 -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 80 -j DNAT --to-destination %s:%d",
             _iface, _uamlisten, uamport);
    if (run_cmd(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTP DNAT rule failed (non-fatal)");

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -I PREROUTING 1 -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 443 -j DNAT --to-destination %s:%d",
             _iface, _uamlisten, https_port);
    if (run_cmd(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTPS DNAT rule failed (non-fatal)");
  }

  syslog(LOG_INFO,
         "ipt_filter_init: ipset " IPSET_NAME
         " + FORWARD rules + DNAT HTTP→%s:%d HTTPS→%s:%d on %s",
         _uamlisten, uamport,
         _uamlisten, (uamuiport > 0) ? uamuiport : uamport,
         _iface);
  return 0;
}

int ipt_filter_add_authed(struct in_addr *ip) {
  char ipstr[INET_ADDRSTRLEN];
  char cmd[256];

  if (!inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr))) {
    syslog(LOG_ERR, "ipt_filter_add_authed: inet_ntop failed");
    return -1;
  }

  snprintf(cmd, sizeof(cmd), "ipset add " IPSET_NAME " %s", ipstr);
  return run_cmd(cmd);
}

int ipt_filter_del_authed(struct in_addr *ip) {
  char ipstr[INET_ADDRSTRLEN];
  char cmd[256];

  if (!inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr))) {
    syslog(LOG_ERR, "ipt_filter_del_authed: inet_ntop failed");
    return -1;
  }

  /* -exist : pas d'erreur si l'IP n'est pas dans le set */
  snprintf(cmd, sizeof(cmd),
           "ipset del " IPSET_NAME " %s 2>/dev/null", ipstr);
  run_cmd(cmd);
  return 0;
}

int ipt_filter_cleanup(void) {
  char cmd[512];

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s"
           " -m set --match-set " IPSET_NAME " src -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s"
           " -m set --match-set " IPSET_NAME " dst -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  if (_uamport) {
    int https_port = (_uamuiport > 0) ? _uamuiport : _uamport;

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 80 -j DNAT --to-destination %s:%d 2>/dev/null",
             _iface, _uamlisten, _uamport);
    run_cmd(cmd);
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -D PREROUTING -i %s"
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 443 -j DNAT --to-destination %s:%d 2>/dev/null",
             _iface, _uamlisten, https_port);
    run_cmd(cmd);
  }

  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");

  syslog(LOG_INFO, "ipt_filter_cleanup: rules and ipset " IPSET_NAME " removed");
  return 0;
}

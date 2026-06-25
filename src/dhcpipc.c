/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * dhcpipc.c — IPC Unix DGRAM entre chilli_dhcp et chilli (main)
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>

#include "dhcpipc.h"

/*
 * Crée et bind une socket serveur sur |path|.
 * Supprime un éventuel socket stale avant le bind.
 * Retourne le fd ou -1 sur erreur.
 */
int dhcpipc_open_server(const char *path) {
  int fd;
  struct sockaddr_un addr;

  if (!path) path = DHCPIPC_DEFAULT_SOCK;

  fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) {
    syslog(LOG_ERR, "dhcpipc_open_server: socket() failed: %s", strerror(errno));
    return -1;
  }

  unlink(path);

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    syslog(LOG_ERR, "dhcpipc_open_server: bind(%s) failed: %s", path, strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

/*
 * Crée une socket client (sans bind) pour l'envoi vers |path|.
 * Le fd peut ensuite être utilisé avec dhcpipc_send() et dhcpipc_recv().
 */
int dhcpipc_open_client(const char *path) {
  int fd;
  (void)path; /* pas de bind côté client */

  fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0) {
    syslog(LOG_ERR, "dhcpipc_open_client: socket() failed: %s", strerror(errno));
    return -1;
  }

  return fd;
}

int dhcpipc_send(int fd, struct sockaddr_un *dest, struct dhcpipc_msg *msg) {
  ssize_t n;

  n = sendto(fd, msg, sizeof(*msg), 0,
             (struct sockaddr *)dest, sizeof(*dest));
  if (n < 0) {
    syslog(LOG_ERR, "dhcpipc_send: sendto() failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

int dhcpipc_recv(int fd, struct dhcpipc_msg *msg, struct sockaddr_un *src) {
  ssize_t n;
  socklen_t len = src ? sizeof(*src) : 0;

  n = recvfrom(fd, msg, sizeof(*msg), 0,
               src ? (struct sockaddr *)src : NULL,
               src ? &len : NULL);
  if (n < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      syslog(LOG_ERR, "dhcpipc_recv: recvfrom() failed: %s", strerror(errno));
    return -1;
  }
  if (n != (ssize_t)sizeof(*msg)) {
    syslog(LOG_ERR, "dhcpipc_recv: short read %zd (expected %zu)", n, sizeof(*msg));
    return -1;
  }
  return 0;
}

/* ---- helpers ---- */

static int _send_to_path(int fd, const char *dest_path, struct dhcpipc_msg *msg) {
  struct sockaddr_un dest;
  memset(&dest, 0, sizeof(dest));
  dest.sun_family = AF_UNIX;
  strncpy(dest.sun_path, dest_path, sizeof(dest.sun_path) - 1);
  return dhcpipc_send(fd, &dest, msg);
}

int dhcpipc_send_new_client(int fd, const char *dest_path,
                            const uint8_t *mac, uint32_t ip, uint16_t vlan) {
  struct dhcpipc_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.type = DHCPIPC_NEW_CLIENT;
  memcpy(msg.mac, mac, PKT_ETH_ALEN);
  msg.ip   = ip;
  msg.vlan = vlan;
  return _send_to_path(fd, dest_path, &msg);
}

int dhcpipc_send_client_gone(int fd, const char *dest_path,
                             const uint8_t *mac, uint32_t ip,
                             dhcpipc_gone_reason_t reason) {
  struct dhcpipc_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.type   = DHCPIPC_CLIENT_GONE;
  memcpy(msg.mac, mac, PKT_ETH_ALEN);
  msg.ip     = ip;
  msg.reason = (uint8_t)reason;
  return _send_to_path(fd, dest_path, &msg);
}

int dhcpipc_send_authstate(int fd, const char *dest_path,
                           const uint8_t *mac, uint32_t ip,
                           uint8_t authstate) {
  struct dhcpipc_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.type      = DHCPIPC_SET_AUTHSTATE;
  memcpy(msg.mac, mac, PKT_ETH_ALEN);
  msg.ip        = ip;
  msg.authstate = authstate;
  return _send_to_path(fd, dest_path, &msg);
}

int dhcpipc_send_kick(int fd, const char *dest_path,
                      const uint8_t *mac, uint32_t ip) {
  struct dhcpipc_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.type = DHCPIPC_KICK_CLIENT;
  memcpy(msg.mac, mac, PKT_ETH_ALEN);
  msg.ip   = ip;
  return _send_to_path(fd, dest_path, &msg);
}

int dhcpipc_send_down(int fd, const char *dest_path,
                      const uint8_t *mac,
                      const uint8_t *pkt, uint16_t pktlen) {
  struct dhcpipc_down_msg msg;
  struct sockaddr_un dest;
  ssize_t n;
  size_t  msglen;

  if (pktlen > DHCPIPC_DOWN_MAX_PKT) {
    syslog(LOG_WARNING, "dhcpipc_send_down: packet too large (%d)", pktlen);
    return -1;
  }

  memcpy(msg.mac, mac, PKT_ETH_ALEN);
  msg.len = pktlen;
  memcpy(msg.data, pkt, pktlen);

  msglen = offsetof(struct dhcpipc_down_msg, data) + pktlen;

  memset(&dest, 0, sizeof(dest));
  dest.sun_family = AF_UNIX;
  strncpy(dest.sun_path, dest_path, sizeof(dest.sun_path) - 1);

  n = sendto(fd, &msg, msglen, 0, (struct sockaddr *)&dest, sizeof(dest));
  if (n < 0) {
    syslog(LOG_ERR, "dhcpipc_send_down: sendto() failed: %s", strerror(errno));
    return -1;
  }
  return 0;
}

int dhcpipc_recv_down(int fd, struct dhcpipc_down_msg *msg) {
  ssize_t n = recv(fd, msg, sizeof(*msg), 0);
  if (n < (ssize_t)offsetof(struct dhcpipc_down_msg, data)) {
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      syslog(LOG_ERR, "dhcpipc_recv_down: recv() failed or too short: %s", strerror(errno));
    return -1;
  }
  return 0;
}

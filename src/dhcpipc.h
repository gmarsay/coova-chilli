/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * dhcpipc.h — IPC protocol between chilli_dhcp and chilli (main)
 *
 * Unix SOCK_DGRAM socket, path configurable via --dhcpsocket
 * (default: /var/run/chilli.dhcp).
 */

#ifndef _DHCPIPC_H
#define _DHCPIPC_H

#include <stdint.h>
#include <sys/un.h>
#include "pkt.h"

#define DHCPIPC_DEFAULT_SOCK "/var/run/chilli.dhcp"

typedef enum {
  DHCPIPC_NEW_CLIENT    = 1,  /* chilli_dhcp → main : nouveau client DHCP */
  DHCPIPC_CLIENT_GONE   = 2,  /* chilli_dhcp → main : client parti         */
  DHCPIPC_SET_AUTHSTATE = 3,  /* main → chilli_dhcp : mise à jour authstate */
  DHCPIPC_KICK_CLIENT   = 4,  /* main → chilli_dhcp : forcer déconnexion   */
  DHCPIPC_SEND_DOWN     = 5,  /* main → chilli_dhcp : paquet IP descendant  */
} dhcpipc_type_t;

/* Socket séparé pour les paquets descendants (plus grand que dhcpipc_msg) */
#define DHCPIPC_DOWN_SUFFIX    ".d.pkt"
#define DHCPIPC_DOWN_MAX_PKT   1600

struct dhcpipc_down_msg {
  uint8_t  mac[PKT_ETH_ALEN]; /* MAC destination (client) */
  uint16_t len;                /* longueur du paquet IP    */
  uint8_t  data[DHCPIPC_DOWN_MAX_PKT];
} __attribute__((packed));

typedef enum {
  DHCPIPC_GONE_RELEASE  = 1,
  DHCPIPC_GONE_TIMEOUT  = 2,
  DHCPIPC_GONE_KICK     = 3,
} dhcpipc_gone_reason_t;

struct dhcpipc_msg {
  uint8_t  type;                /* dhcpipc_type_t                       */
  uint8_t  mac[PKT_ETH_ALEN];  /* MAC client                           */
  uint32_t ip;                  /* IP client (network byte order)       */
  uint8_t  authstate;           /* DHCP_AUTH_* (pour SET_AUTHSTATE)     */
  uint8_t  reason;              /* dhcpipc_gone_reason_t (CLIENT_GONE)  */
  uint16_t vlan;                /* VLAN ID si applicable                */
} __attribute__((packed));

int dhcpipc_open_server(const char *path);
int dhcpipc_open_client(const char *path);
int dhcpipc_send(int fd, struct sockaddr_un *dest, struct dhcpipc_msg *msg);
int dhcpipc_recv(int fd, struct dhcpipc_msg *msg, struct sockaddr_un *src);

/* Helpers */
int dhcpipc_send_new_client(int fd, const char *dest_path,
                            const uint8_t *mac, uint32_t ip, uint16_t vlan);
int dhcpipc_send_client_gone(int fd, const char *dest_path,
                             const uint8_t *mac, uint32_t ip,
                             dhcpipc_gone_reason_t reason);
int dhcpipc_send_authstate(int fd, const char *dest_path,
                           const uint8_t *mac, uint32_t ip,
                           uint8_t authstate);
int dhcpipc_send_kick(int fd, const char *dest_path,
                      const uint8_t *mac, uint32_t ip);

/* Downlink: envoie un paquet IP brut vers chilli_dhcp pour injection L2 */
int dhcpipc_send_down(int fd, const char *dest_path,
                      const uint8_t *mac,
                      const uint8_t *pkt, uint16_t pktlen);
int dhcpipc_recv_down(int fd, struct dhcpipc_down_msg *msg);

#endif /* _DHCPIPC_H */

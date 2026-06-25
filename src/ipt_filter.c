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

/* Interface DHCP mémorisée à l'init pour le cleanup */
static char _iface[64];

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

int ipt_filter_init(const char *iface) {
  char cmd[512];

  strncpy(_iface, iface ? iface : "", sizeof(_iface) - 1);
  _iface[sizeof(_iface) - 1] = '\0';

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

  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");

  /* Crée le set (hash:ip, timeout 1h) */
  if (run_cmd("ipset create " IPSET_NAME
              " hash:ip hashsize 1024 maxelem 65536 timeout 3600") != 0) {
    syslog(LOG_ERR, "ipt_filter_init: ipset create failed");
    return -1;
  }

  /* Règle src : trafic émis par un client authentifié */
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
    /* rollback src rule */
    snprintf(cmd, sizeof(cmd),
             IPTABLES " -D FORWARD -i %s"
             " -m set --match-set " IPSET_NAME " src -j ACCEPT",
             _iface);
    run_cmd(cmd);
    run_cmd("ipset destroy " IPSET_NAME);
    return -1;
  }

  syslog(LOG_INFO,
         "ipt_filter_init: ipset " IPSET_NAME
         " + iptables-legacy FORWARD rules on %s", _iface);
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

  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");

  syslog(LOG_INFO, "ipt_filter_cleanup: ipset " IPSET_NAME " destroyed");
  return 0;
}

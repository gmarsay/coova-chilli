/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * ipt_filter.c — Filtrage kernel via iptables-legacy + ipset
 *
 * Utilise des chaînes dédiées CHILLI_FWD et CHILLI_NAT pour un
 * cleanup atomique (flush de chaîne) et éviter les accumulations
 * de règles lors de redémarrages.
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "ipt_filter.h"

#define IPSET_NAME    "chilli_authed"
#define IPTABLES      "iptables-legacy"
#define CHAIN_FWD     "CHILLI_FWD"
#define CHAIN_NAT     "CHILLI_NAT"

/* État mémorisé pour le cleanup */
static char     _iface[64];
static char     _uamlisten[INET_ADDRSTRLEN];
static uint16_t _uamport;
static uint16_t _uamuiport;

/* ------------------------------------------------------------------ */
/* run_cmd : exécute cmd, retourne 0 si succès                          */
/* ------------------------------------------------------------------ */
static int run_cmd(const char *cmd) {
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    syslog(LOG_ERR, "ipt_filter: popen() failed for: %s", cmd);
    return -1;
  }
  int rc = pclose(fp);
  if (rc != 0)
    syslog(LOG_DEBUG, "ipt_filter: rc=%d: %s", rc, cmd);
  return rc == 0 ? 0 : -1;
}

/* run_cmd_log : comme run_cmd mais capture stderr et le logue en ERR */
static int run_cmd_log(const char *cmd) {
  char full[600];
  char line[256];
  FILE *fp;
  int  rc;

  snprintf(full, sizeof(full), "%s 2>&1", cmd);
  fp = popen(full, "r");
  if (!fp) {
    syslog(LOG_ERR, "ipt_filter: popen() failed for: %s", cmd);
    return -1;
  }
  /* Lit la première ligne d'erreur éventuelle */
  if (fgets(line, sizeof(line), fp)) {
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    syslog(LOG_ERR, "ipt_filter [%s]: %s", cmd, line);
  }
  rc = pclose(fp);
  return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* _flush_chains : vide nos chaînes pour libérer les refs à l'ipset    */
/* ------------------------------------------------------------------ */
static void _flush_chains(void) {
  /* Vide les chaînes dédiées → toutes les refs à chilli_authed supprimées */
  run_cmd(IPTABLES " -t nat -F " CHAIN_NAT " 2>/dev/null");
  run_cmd(IPTABLES " -F " CHAIN_FWD " 2>/dev/null");

  /* Rétrocompatibilité : règles directes dans PREROUTING/FORWARD */
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
  /* Peut en rester plusieurs → boucle */
  int i;
  for (i = 0; i < 5; i++) {
    if (run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " IPSET_NAME " src"
                " -p tcp --dport 80 -j REDIRECT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " IPSET_NAME " src"
                " -p tcp --dport 443 -j REDIRECT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " IPSET_NAME " src"
                " -p tcp --dport 80 -j DNAT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " IPSET_NAME " src"
                " -p tcp --dport 443 -j DNAT 2>/dev/null") != 0)
      break;
  }
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

  /* 1. Vider les chaînes → libère toutes les références à l'ipset */
  _flush_chains();

  /* 2. Supprimer les sauts vers nos chaînes (s'ils existent) */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -D PREROUTING -i %s -j " CHAIN_NAT " 2>/dev/null",
           _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j " CHAIN_FWD " 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j " CHAIN_FWD " 2>/dev/null", _iface);
  run_cmd(cmd);

  /* Nettoyage DROP FORWARD précédents */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  /* 3. Détruire et recréer l'ipset */
  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
  if (run_cmd_log("ipset create " IPSET_NAME
                  " hash:ip hashsize 1024 maxelem 65536 timeout 3600") != 0) {
    /* Le set existe encore (référence externe) — flush et réutilise */
    syslog(LOG_WARNING,
           "ipt_filter_init: ipset destroy failed (external ref?); flushing");
    if (run_cmd_log("ipset flush " IPSET_NAME) != 0) {
      syslog(LOG_ERR, "ipt_filter_init: cannot create or flush ipset, aborting");
      return -1;
    }
  }

  /* 4. Créer nos chaînes dédiées */
  run_cmd(IPTABLES " -t nat -N " CHAIN_NAT " 2>/dev/null");
  run_cmd(IPTABLES " -N " CHAIN_FWD " 2>/dev/null");

  /* 5. Ajouter les sauts depuis PREROUTING et FORWARD vers nos chaînes */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -I PREROUTING 1 -i %s -j " CHAIN_NAT, _iface);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: NAT PREROUTING jump failed");
    run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -i %s -j " CHAIN_FWD, _iface);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD in jump failed");
    run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -o %s -j " CHAIN_FWD, _iface);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD out jump failed");
    run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
    return -1;
  }

  /* 6. Règles FORWARD dans CHILLI_FWD */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A " CHAIN_FWD
           " -m set --match-set " IPSET_NAME " src -j ACCEPT");
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD ACCEPT src failed");
    run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A " CHAIN_FWD
           " -m set --match-set " IPSET_NAME " dst -j ACCEPT");
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD ACCEPT dst failed");
    run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");
    return -1;
  }

  run_cmd(IPTABLES " -A " CHAIN_FWD " -j DROP");

  /* 7. Règles DNAT dans CHILLI_NAT */
  if (uamport) {
    int https_port = (uamuiport > 0) ? uamuiport : uamport;

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -A " CHAIN_NAT
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 80 -j DNAT --to-destination %s:%d",
             _uamlisten, uamport);
    if (run_cmd_log(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTP DNAT failed (check xt_DNAT module)");

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -A " CHAIN_NAT
             " -m set ! --match-set " IPSET_NAME " src"
             " -p tcp --dport 443 -j DNAT --to-destination %s:%d",
             _uamlisten, https_port);
    if (run_cmd_log(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTPS DNAT failed (check xt_DNAT module)");
  }

  syslog(LOG_INFO,
         "ipt_filter_init: OK — DNAT HTTP→%s:%d HTTPS→%s:%d on %s",
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

  snprintf(cmd, sizeof(cmd),
           "ipset del " IPSET_NAME " %s 2>/dev/null", ipstr);
  run_cmd(cmd);
  return 0;
}

int ipt_filter_cleanup(void) {
  char cmd[512];

  /* Vider les chaînes libère toutes les références à l'ipset */
  _flush_chains();

  /* Supprimer les sauts */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -D PREROUTING -i %s -j " CHAIN_NAT " 2>/dev/null",
           _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j " CHAIN_FWD " 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j " CHAIN_FWD " 2>/dev/null", _iface);
  run_cmd(cmd);

  /* DROP FORWARD legacy */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  /* Détruire les chaînes */
  run_cmd(IPTABLES " -t nat -X " CHAIN_NAT " 2>/dev/null");
  run_cmd(IPTABLES " -X " CHAIN_FWD " 2>/dev/null");

  /* Détruire l'ipset */
  run_cmd("ipset destroy " IPSET_NAME " 2>/dev/null");

  syslog(LOG_INFO, "ipt_filter_cleanup: done");
  return 0;
}

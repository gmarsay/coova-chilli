/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * ipt_filter.c — Filtrage kernel via iptables-legacy + ipset
 *
 * Utilise des chaînes dédiées CHILLI_FWD_<nasid> et CHILLI_NAT_<nasid>
 * (et l'ipset chilli_authed_<nasid>) pour un cleanup atomique (flush de
 * chaîne), éviter les accumulations de règles lors de redémarrages et
 * permettre plusieurs instances chilli sur le même hôte.
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "ipt_filter.h"

#define IPTABLES      "iptables-legacy -w 5"

/* Anciens noms fixes (versions précédentes, une seule instance par hôte) */
#define LEGACY_IPSET      "chilli_authed"
#define LEGACY_CHAIN_FWD  "CHILLI_FWD"
#define LEGACY_CHAIN_NAT  "CHILLI_NAT"

/* Longueur max du suffixe : "chilli_authed_" (14) + 17 = 31 (limite ipset),
 * "CHILLI_FWD_" (11) + 17 = 28 (limite chaîne iptables). */
#define SUFFIX_MAX    17

/* État mémorisé pour le cleanup */
static char     _set[32];
static char     _fwd[32];
static char     _nat[32];
static char     _iface[64];
static char     _uamlisten[INET_ADDRSTRLEN];
static uint16_t _uamport;
static uint16_t _uamuiport;

/* ------------------------------------------------------------------ */
/* ipt_filter_names : noms ipset/chaînes dérivés de l'instance (nasid)  */
/* ------------------------------------------------------------------ */
int ipt_filter_names(const char *instance,
                     char *set, size_t setlen,
                     char *fwd, size_t fwdlen,
                     char *nat, size_t natlen) {
  char sfx[SUFFIX_MAX + 1];
  size_t i;
  int changed = 0;

  if (!instance || !*instance)
    instance = "default";

  /* Sécurité : le suffixe est interpolé dans des commandes popen(),
   * seuls [A-Za-z0-9_] sont conservés. */
  for (i = 0; instance[i] && i < SUFFIX_MAX; i++) {
    char c = instance[i];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_') {
      sfx[i] = c;
    } else {
      sfx[i] = '_';
      changed = 1;
    }
  }
  sfx[i] = '\0';
  if (instance[i])
    changed = 1; /* tronqué */

  snprintf(set, setlen, "chilli_authed_%s", sfx);
  snprintf(fwd, fwdlen, "CHILLI_FWD_%s", sfx);
  snprintf(nat, natlen, "CHILLI_NAT_%s", sfx);
  return changed;
}

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
  char cmd[512];

  /* Vide les chaînes dédiées → toutes les refs à notre ipset supprimées */
  snprintf(cmd, sizeof(cmd), IPTABLES " -t nat -F %s 2>/dev/null", _nat);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd), IPTABLES " -F %s 2>/dev/null", _fwd);
  run_cmd(cmd);

  /* Rétrocompatibilité : règles directes dans PREROUTING/FORWARD
   * (anciennes versions, ipset au nom fixe) */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s"
           " -m set --match-set " LEGACY_IPSET " src -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s"
           " -m set --match-set " LEGACY_IPSET " dst -j ACCEPT 2>/dev/null",
           _iface);
  run_cmd(cmd);
  /* Peut en rester plusieurs → boucle */
  int i;
  for (i = 0; i < 5; i++) {
    if (run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " LEGACY_IPSET " src"
                " -p tcp --dport 80 -j REDIRECT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " LEGACY_IPSET " src"
                " -p tcp --dport 443 -j REDIRECT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " LEGACY_IPSET " src"
                " -p tcp --dport 80 -j DNAT 2>/dev/null") != 0 &&
        run_cmd(IPTABLES " -t nat -D PREROUTING"
                " -m set ! --match-set " LEGACY_IPSET " src"
                " -p tcp --dport 443 -j DNAT 2>/dev/null") != 0)
      break;
  }
}

/* ------------------------------------------------------------------ */
/* API publique                                                          */
/* ------------------------------------------------------------------ */

int ipt_filter_init(const char *iface, struct in_addr uamlisten,
                    uint16_t uamport, uint16_t uamuiport,
                    const char *instance) {
  char cmd[512];

  if (ipt_filter_names(instance, _set, sizeof(_set), _fwd, sizeof(_fwd),
                       _nat, sizeof(_nat)))
    syslog(LOG_WARNING,
           "ipt_filter_init: radiusnasid sanitized/truncated for netfilter"
           " names: ipset=%s chains=%s,%s", _set, _fwd, _nat);

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
           IPTABLES " -t nat -D PREROUTING -i %s -j %s 2>/dev/null",
           _iface, _nat);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j %s 2>/dev/null", _iface, _fwd);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j %s 2>/dev/null", _iface, _fwd);
  run_cmd(cmd);

  /* 2b. Migration : sauts vers les anciennes chaînes au nom fixe, pour
   * notre interface uniquement. */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -D PREROUTING -i %s -j " LEGACY_CHAIN_NAT
           " 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j " LEGACY_CHAIN_FWD " 2>/dev/null",
           _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j " LEGACY_CHAIN_FWD " 2>/dev/null",
           _iface);
  run_cmd(cmd);
  /* ponytail: pas de flush des objets legacy — -X et destroy échouent tant
   * qu'une instance d'ancienne version les référence encore ; ils ne sont
   * supprimés que lorsque plus personne ne les utilise. */
  run_cmd(IPTABLES " -t nat -X " LEGACY_CHAIN_NAT " 2>/dev/null");
  run_cmd(IPTABLES " -X " LEGACY_CHAIN_FWD " 2>/dev/null");
  run_cmd("ipset destroy " LEGACY_IPSET " 2>/dev/null");

  /* Nettoyage DROP FORWARD précédents */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  /* 3. Détruire et recréer l'ipset */
  snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           "ipset create %s hash:ip hashsize 1024 maxelem 65536 timeout 3600",
           _set);
  if (run_cmd_log(cmd) != 0) {
    /* Le set existe encore (référence externe) — flush et réutilise */
    syslog(LOG_WARNING,
           "ipt_filter_init: ipset destroy failed (external ref?); flushing");
    snprintf(cmd, sizeof(cmd), "ipset flush %s", _set);
    if (run_cmd_log(cmd) != 0) {
      syslog(LOG_ERR, "ipt_filter_init: cannot create or flush ipset, aborting");
      return -1;
    }
  }

  /* 4. Créer nos chaînes dédiées */
  snprintf(cmd, sizeof(cmd), IPTABLES " -t nat -N %s 2>/dev/null", _nat);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd), IPTABLES " -N %s 2>/dev/null", _fwd);
  run_cmd(cmd);

  /* 5. Ajouter les sauts depuis PREROUTING et FORWARD vers nos chaînes */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -I PREROUTING 1 -i %s -j %s", _iface, _nat);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: NAT PREROUTING jump failed");
    snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
    run_cmd(cmd);
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -i %s -j %s", _iface, _fwd);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD in jump failed");
    snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
    run_cmd(cmd);
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -I FORWARD 1 -o %s -j %s", _iface, _fwd);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD out jump failed");
    snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
    run_cmd(cmd);
    return -1;
  }

  /* 6. Règles FORWARD dans CHILLI_FWD_<nasid> */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A %s -m set --match-set %s src -j ACCEPT", _fwd, _set);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD ACCEPT src failed");
    snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
    run_cmd(cmd);
    return -1;
  }

  snprintf(cmd, sizeof(cmd),
           IPTABLES " -A %s -m set --match-set %s dst -j ACCEPT", _fwd, _set);
  if (run_cmd_log(cmd) != 0) {
    syslog(LOG_ERR, "ipt_filter_init: FORWARD ACCEPT dst failed");
    snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
    run_cmd(cmd);
    return -1;
  }

  snprintf(cmd, sizeof(cmd), IPTABLES " -A %s -j DROP", _fwd);
  run_cmd(cmd);

  /* 7. Règles DNAT dans CHILLI_NAT_<nasid> */
  if (uamport) {
    int https_port = (uamuiport > 0) ? uamuiport : uamport;

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -A %s -m set ! --match-set %s src"
             " -p tcp --dport 80 -j DNAT --to-destination %s:%d",
             _nat, _set, _uamlisten, uamport);
    if (run_cmd_log(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTP DNAT failed (check xt_DNAT module)");

    snprintf(cmd, sizeof(cmd),
             IPTABLES " -t nat -A %s -m set ! --match-set %s src"
             " -p tcp --dport 443 -j DNAT --to-destination %s:%d",
             _nat, _set, _uamlisten, https_port);
    if (run_cmd_log(cmd) != 0)
      syslog(LOG_WARNING, "ipt_filter_init: HTTPS DNAT failed (check xt_DNAT module)");
  }

  syslog(LOG_INFO,
         "ipt_filter_init: OK — DNAT HTTP→%s:%d HTTPS→%s:%d on %s"
         " (ipset=%s chains=%s,%s)",
         _uamlisten, uamport,
         _uamlisten, (uamuiport > 0) ? uamuiport : uamport,
         _iface, _set, _fwd, _nat);
  return 0;
}

int ipt_filter_add_authed(struct in_addr *ip) {
  char ipstr[INET_ADDRSTRLEN];
  char cmd[256];

  if (!inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr))) {
    syslog(LOG_ERR, "ipt_filter_add_authed: inet_ntop failed");
    return -1;
  }

  snprintf(cmd, sizeof(cmd), "ipset add %s %s", _set, ipstr);
  return run_cmd(cmd);
}

int ipt_filter_del_authed(struct in_addr *ip) {
  char ipstr[INET_ADDRSTRLEN];
  char cmd[256];

  if (!inet_ntop(AF_INET, ip, ipstr, sizeof(ipstr))) {
    syslog(LOG_ERR, "ipt_filter_del_authed: inet_ntop failed");
    return -1;
  }

  snprintf(cmd, sizeof(cmd), "ipset del %s %s 2>/dev/null", _set, ipstr);
  run_cmd(cmd);
  return 0;
}

int ipt_filter_cleanup(void) {
  char cmd[512];

  /* Vider les chaînes libère toutes les références à l'ipset */
  _flush_chains();

  /* Supprimer les sauts */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -t nat -D PREROUTING -i %s -j %s 2>/dev/null",
           _iface, _nat);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j %s 2>/dev/null", _iface, _fwd);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j %s 2>/dev/null", _iface, _fwd);
  run_cmd(cmd);

  /* DROP FORWARD legacy */
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -i %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd),
           IPTABLES " -D FORWARD -o %s -j DROP 2>/dev/null", _iface);
  run_cmd(cmd);

  /* Détruire les chaînes */
  snprintf(cmd, sizeof(cmd), IPTABLES " -t nat -X %s 2>/dev/null", _nat);
  run_cmd(cmd);
  snprintf(cmd, sizeof(cmd), IPTABLES " -X %s 2>/dev/null", _fwd);
  run_cmd(cmd);

  /* Détruire l'ipset */
  snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null", _set);
  run_cmd(cmd);

  syslog(LOG_INFO, "ipt_filter_cleanup: done");
  return 0;
}

/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * ipt_filter.h — Abstraction filtrage kernel pour les clients authentifiés
 *
 * Implémentation via iptables-legacy + ipset (hash:ip "chilli_authed").
 * Deux règles ACCEPT sont insérées en tête de la chaîne FORWARD pour
 * les clients dont l'IP est dans le set ; le reste du trafic suit les
 * règles iptables existantes.
 *
 * Dépendances système : iptables-legacy, ipset (xt_set kmod).
 */

#ifndef _IPT_FILTER_H
#define _IPT_FILTER_H

#include <netinet/in.h>

/*
 * Initialise l'ipset et les règles iptables-legacy.
 * |iface|     : interface DHCP (ex. "eth1").
 * |uamlisten| : IP locale sur laquelle chilli_redir écoute (ex. 10.250.0.1).
 * |uamport|   : port UAM HTTP (ex. 3990) — trafic port 80 redirigé ici.
 * |uamuiport| : port UAM HTTPS (ex. 3991, 0 = désactivé) — trafic port 443
 *               redirigé ici si > 0, sinon vers uamport.
 * Utilise DNAT pour fixer IP+port explicitement (REDIRECT ne change que le port).
 * Doit être appelé une seule fois au démarrage de chilli (main).
 */
int ipt_filter_init(const char *iface, struct in_addr uamlisten,
                    uint16_t uamport, uint16_t uamuiport);

/* Ajoute une IP dans le set "chilli_authed" (client authentifié). */
int ipt_filter_add_authed(struct in_addr *ip);

/* Retire une IP du set "chilli_authed". */
int ipt_filter_del_authed(struct in_addr *ip);

/* Supprime les règles iptables et détruit l'ipset à l'arrêt. */
int ipt_filter_cleanup(void);

#endif /* _IPT_FILTER_H */

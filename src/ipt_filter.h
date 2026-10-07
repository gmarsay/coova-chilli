/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * ipt_filter.h — Abstraction filtrage kernel pour les clients authentifiés
 *
 * Implémentation via iptables-legacy + ipset (hash:ip).
 * Les noms sont propres à chaque instance, suffixés par le radiusnasid
 * assaini (cf. ipt_filter_names) : ipset "chilli_authed_<s>", chaînes
 * "CHILLI_FWD_<s>" et "CHILLI_NAT_<s>". Plusieurs instances chilli
 * peuvent ainsi cohabiter sur le même hôte (radiusnasid distincts).
 * Des sauts en tête de FORWARD / PREROUTING (nat) mènent à ces chaînes ;
 * le reste du trafic suit les règles iptables existantes.
 *
 * Dépendances système : iptables-legacy, ipset (xt_set kmod).
 */

#ifndef _IPT_FILTER_H
#define _IPT_FILTER_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/*
 * Calcule les noms ipset/chaînes à partir de |instance| (radiusnasid).
 * Suffixe : tout caractère hors [A-Za-z0-9_] devient '_', tronqué à 17
 * caractères ; NULL ou "" → "default".
 * Résultat : chilli_authed_<s> (≤ 31, limite ipset), CHILLI_FWD_<s> et
 * CHILLI_NAT_<s> (≤ 28, limite chaîne iptables).
 * Retourne 1 si le suffixe a été modifié (substitution ou troncature), 0 sinon.
 */
int ipt_filter_names(const char *instance,
                     char *set, size_t setlen,
                     char *fwd, size_t fwdlen,
                     char *nat, size_t natlen);

/*
 * Initialise l'ipset et les règles iptables-legacy.
 * |iface|     : interface DHCP (ex. "eth1").
 * |uamlisten| : IP locale sur laquelle chilli_redir écoute (ex. 10.250.0.1).
 * |uamport|   : port UAM HTTP (ex. 3990) — trafic port 80 redirigé ici.
 * |uamuiport| : port UAM HTTPS (ex. 3991, 0 = désactivé) — trafic port 443
 *               redirigé ici si > 0, sinon vers uamport.
 * |instance|  : identifiant d'instance (radiusnasid), cf. ipt_filter_names.
 * Utilise DNAT pour fixer IP+port explicitement (REDIRECT ne change que le port).
 * Doit être appelé une seule fois au démarrage de chilli (main).
 */
int ipt_filter_init(const char *iface, struct in_addr uamlisten,
                    uint16_t uamport, uint16_t uamuiport,
                    const char *instance);

/* Ajoute une IP dans le set "chilli_authed_<s>" (client authentifié). */
int ipt_filter_add_authed(struct in_addr *ip);

/* Retire une IP du set "chilli_authed_<s>". */
int ipt_filter_del_authed(struct in_addr *ip);

/* Supprime les règles iptables et détruit l'ipset à l'arrêt. */
int ipt_filter_cleanup(void);

#endif /* _IPT_FILTER_H */

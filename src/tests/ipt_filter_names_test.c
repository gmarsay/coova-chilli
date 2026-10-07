/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Test de ipt_filter_names : assainissement / troncature du suffixe
 * dérivé de radiusnasid. N'exécute aucune commande iptables/ipset.
 */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ipt_filter.h"

static char set[32], fwd[32], nat[32];

static int names(const char *instance) {
  int rc = ipt_filter_names(instance, set, sizeof(set), fwd, sizeof(fwd),
                            nat, sizeof(nat));
  assert(strlen(set) <= 31);
  assert(strlen(fwd) <= 28);
  assert(strlen(nat) <= 28);
  return rc;
}

int main(void) {
  assert(names("nas01") == 0);
  assert(!strcmp(set, "chilli_authed_nas01"));
  assert(!strcmp(fwd, "CHILLI_FWD_nas01"));
  assert(!strcmp(nat, "CHILLI_NAT_nas01"));

  assert(names("hotspot-paris.01") == 1);
  assert(!strcmp(set, "chilli_authed_hotspot_paris_01"));
  assert(!strcmp(fwd, "CHILLI_FWD_hotspot_paris_01"));
  assert(!strcmp(nat, "CHILLI_NAT_hotspot_paris_01"));

  /* 20 caractères → tronqué à 17 */
  assert(names("abcdefghijklmnopqrst") == 1);
  assert(!strcmp(set, "chilli_authed_abcdefghijklmnopq"));
  assert(!strcmp(fwd, "CHILLI_FWD_abcdefghijklmnopq"));
  assert(!strcmp(nat, "CHILLI_NAT_abcdefghijklmnopq"));

  /* Exactement 17 caractères valides → inchangé */
  assert(names("abcdefghijklmnopq") == 0);

  /* Tentative d'injection shell → neutralisée */
  assert(names("x;rm -rf /") == 1);
  assert(!strcmp(set, "chilli_authed_x_rm__rf__"));

  assert(names(NULL) == 0);
  assert(!strcmp(set, "chilli_authed_default"));
  assert(!strcmp(fwd, "CHILLI_FWD_default"));
  assert(!strcmp(nat, "CHILLI_NAT_default"));

  assert(names("") == 0);
  assert(!strcmp(set, "chilli_authed_default"));

  printf("ipt_filter_names_test: OK\n");
  return 0;
}

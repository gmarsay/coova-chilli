/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * main-redir.c — Point d'entrée du processus chilli_redir
 *
 * chilli_redir écoute sur uamport (et uamuiport si activé), accepte les
 * connexions HTTP des clients non authentifiés, et envoie les réponses de
 * redirection UAM. L'état de session est interrogé auprès du processus
 * principal via le socket Unix chilli.ipc.
 *
 * Lancement : chilli_redir -b <binconfig>
 */

#define MAIN_FILE

#include "chilli.h"
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

struct options_t _options;

static volatile int keep_going = 1;

static void sig_handler(int signum) {
  if (signum == SIGTERM || signum == SIGINT)
    keep_going = 0;
}

int main(int argc, char **argv) {
  struct redir_t *redir = NULL;
  select_ctx sctx;

#ifdef LOG_PERROR
  openlog("chilli_redir", LOG_PID | LOG_PERROR, LOG_DAEMON);
#else
  openlog("chilli_redir", LOG_PID, LOG_DAEMON);
#endif

  if (!process_options(argc, argv, 0)) {
    syslog(LOG_ERR, "chilli_redir: failed to load options");
    return 1;
  }

  signal(SIGTERM, sig_handler);
  signal(SIGINT,  sig_handler);
  signal(SIGHUP,  SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);  /* auto-reap forked HTTP handler children */

  if (redir_new(&redir, &_options.uamlisten, _options.uamport,
#ifdef ENABLE_UAMUIPORT
                _options.uamuiport
#else
                0
#endif
                )) {
    syslog(LOG_ERR, "chilli_redir: redir_new failed");
    return 1;
  }

  redir_set(redir, NULL, _options.debug);

  if (redir_listen(redir)) {
    syslog(LOG_ERR, "chilli_redir: redir_listen failed");
    redir_free(redir);
    return 1;
  }

  syslog(LOG_INFO, "chilli_redir: started, UAM port %d", _options.uamport);

  memset(&sctx, 0, sizeof(sctx));
  if (net_select_init(&sctx))
    syslog(LOG_ERR, "chilli_redir: net_select_init failed");

  net_select_reg(&sctx, redir->fd[0], SELECT_READ,
                 (select_callback)redir_accept, redir, 0);
  if (redir->fd[1])
    net_select_reg(&sctx, redir->fd[1], SELECT_READ,
                   (select_callback)redir_accept, redir, 1);

  while (keep_going) {
    int status;

    if (net_select_prepare(&sctx))
      syslog(LOG_ERR, "chilli_redir: net_select_prepare failed");

    status = net_select(&sctx);
    if (status > 0)
      net_run_selected(&sctx, status);
  }

  syslog(LOG_INFO, "chilli_redir: shutting down");
  redir_free(redir);
  return 0;
}

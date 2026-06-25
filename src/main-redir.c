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
#include "redir.h"
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

struct options_t _options;

static volatile int keep_going = 1;

static void sig_handler(int signum) {
  if (signum == SIGTERM || signum == SIGINT)
    keep_going = 0;
}

/*
 * Obtient l'état de session depuis le processus principal via chilli.ipc.
 * Envoie REDIR_MSG_STATUS_TYPE et lit en retour un redir_conn_t.
 */
static int cb_getstate_via_ipc(struct redir_t *redir,
                               struct sockaddr_in *address,
                               struct sockaddr_in *baddress,
                               struct redir_conn_t *conn) {
  char filedest[512];
  struct sockaddr_un remote;
  struct redir_msg_t msg;
  int s;
  ssize_t n;
  size_t len;

  (void)redir;

  statedir_file(filedest, sizeof(filedest), _options.unixipc, "chilli.ipc");

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    syslog(LOG_ERR, "cb_getstate_via_ipc: socket() failed: %s", strerror(errno));
    return -1;
  }

  memset(&remote, 0, sizeof(remote));
  remote.sun_family = AF_UNIX;
  strlcpy(remote.sun_path, filedest, sizeof(remote.sun_path));
  len = offsetof(struct sockaddr_un, sun_path) + strlen(remote.sun_path);

  if (safe_connect(s, (struct sockaddr *)&remote, len) < 0) {
    syslog(LOG_DEBUG, "cb_getstate_via_ipc: connect to %s failed: %s",
           filedest, strerror(errno));
    safe_close(s);
    return -1;
  }

  memset(&msg, 0, sizeof(msg));
  msg.mtype = REDIR_MSG_STATUS_TYPE;
  memcpy(&msg.mdata.address,  address,  sizeof(msg.mdata.address));
  memcpy(&msg.mdata.baddress, baddress, sizeof(msg.mdata.baddress));

  if (safe_write(s, &msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
    syslog(LOG_ERR, "cb_getstate_via_ipc: write failed: %s", strerror(errno));
    safe_close(s);
    return -1;
  }

  /* Lire la réponse — main écrit un redir_conn_t si session trouvée */
  memset(conn, 0, sizeof(*conn));
  n = safe_read(s, conn, sizeof(*conn));
  safe_close(s);

  if (n != (ssize_t)sizeof(*conn)) {
    syslog(LOG_DEBUG, "cb_getstate_via_ipc: no session for %s",
           inet_ntoa(address->sin_addr));
    return -1;
  }

  return conn->s_state.authenticated == 1;
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
  redir_set_cb_getstate(redir, cb_getstate_via_ipc);

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

/* defines the simple protocol between the daemon and the PAM module
 *
 * the client (PAM module) sends a welcome packet and uid, then:
 *
 * the server receives welcome packet, uid, gid, homedir length,
 * homedir in word sized pieces; for each it sends MSG_OK
 *
 * the client acknowledges it, sends MSG_OK back
 *
 * if things are not ready serverside:
 *   server sends MSG_OK_WAIT
 *   server waits for dinit to come up
 *
 * server sends MSG_OK_DONE
 * client continues login
 *
 * Copyright 2021 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef DINIT_USERSERVD_PROTOCOL_HH
#define DINIT_USERSERVD_PROTOCOL_HH

#include <sys/un.h>

#define SOCK_PATH "/run/dinit-userservd"
#define DAEMON_SOCK SOCK_PATH"/control.sock"
#define USER_PATH SOCK_PATH"/%u"
#define USER_FIFO USER_PATH"/dinit.fifo"
#define USER_DIR USER_PATH"/dinit.XXXXXX"

/* sanity check */
static_assert(
    sizeof(DAEMON_SOCK) > sizeof(decltype(sockaddr_un{}.sun_family))
);

/* maximum length of the homedir path we can receive */
#define HDIRLEN_MAX 1024

/* protocol */

/* this is a regular unsigned int */
enum {
    /* sent by the server as an acknowledgement of a message, and by
     * the client once it has sent all the session info
     */
    MSG_OK = 0x1,
    MSG_OK_WAIT, /* login, wait */
    MSG_OK_DONE, /* ready, proceed */
    /* sent by server on errors */
    MSG_ERR,
    /* welcome packet */
    MSG_WELCOME = 0x1337
};

#endif

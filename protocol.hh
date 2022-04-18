/* defines the simple protocol between the daemon and the PAM module
 *
 * Copyright 2021 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef DINIT_USERSERVD_PROTOCOL_HH
#define DINIT_USERSERVD_PROTOCOL_HH

#include <sys/un.h>

#define RUNDIR_PATH "/run/user/%u"
#define SOCK_PATH "/run/dinit-userservd"
#define DAEMON_SOCK SOCK_PATH"/control.sock"
#define USER_PATH SOCK_PATH"/%u"
#define USER_FIFO USER_PATH"/dinit.fifo"
#define USER_DIR USER_PATH"/dinit.XXXXXX"

/* sanity check */
static_assert(
    sizeof(DAEMON_SOCK) > sizeof(decltype(sockaddr_un{}.sun_family))
);

/* maximum length of a directory path we can receive */
#define DIRLEN_MAX 1024

/* protocol messages
 *
 * this is a simple protocol consisting of uint-sized messages; each
 * message carries the type (4 bits) and optionally auxiliary data
 * (only some messages; MSG_DATA and MSG_REQ_RDATA)
 *
 * dinit-userservd is the server; the pam module is the client
 *
 * the client connects to DAEMON_SOCK (seqpacket sockets are used)
 *
 * from there, the following sequence happens:
 *
 * CLIENT: sends MSG_START and enters a message loop (state machine)
 * SERVER: receives it and adds the session into pending connections,
 *         then responds MSG_OK
 * CLIENT: consumes MSG_OK, sends MSG_DATA with user id attached
 * SERVER: responds MSG_OK
 * CLIENT: consumes MSG_OK, sends MSG_DATA with group id attached
 * SERVER: responds MSG_OK
 * CLIENT: consumes MSG_OK, sends MSG_DATA with homedir length attached
 * SERVER: validates, allocates a data buffer and responds MSG_OK
 * loop:
 *   CLIENT: consumes MSG_OK, if there is any of homedir left unsent,
 *           it sends it; otherwise loop ends
 *   SERVER: adds to buffer, responds MSG_OK
 * CLIENT: consumes MSG_OK, sends MSG_DATA with rundir length attached;
 *         if no rundir is set clientside, sends 0 instead and the server
 *         will make its own; if rundir handling is intentionally skipped,
 *         DIRLEN_MAX+1 is sent instead and the server will disregard it
 * loop: same as above, but for rundir (nothing is sent for 0 length);
 *       at the end, server acknowledges the session and replies MSG_OK
 * CLIENT: sends MSG_OK to confirm everything is ready on its side
 * SERVER: if service manager for the user is already running, responds
 *         with MSG_OK_DONE; else initiates startup and responds with
 *         MSG_OK_WAIT
 * CLIENT: if MSG_OK_WAIT was received, waits for a message
 * SERVER: once service manager starts, MSG_OK_DONE is sent
 * CLIENT: sends MSG_REQ_RLEN
 * SERVER: responds with MSG_DATA with rundir length (0 if not known)
 * loop:
 *   CLIENT: sends MSG_REQ_RDATA with number of remaining bytes of rundir
 *           that are yet to be received
 *   SERVER: responds with a MSG_DATA packet until none is left
 * CLIENT: finishes startup, exports XDG_RUNTIME_DIR if needed as well
 *         as DBUS_SESSION_BUS_ADDRESS, and everything is done
 */

/* this is a regular unsigned int */
enum {
    /* sent by the server as an acknowledgement of a message, and by
     * the client once it has sent all the session info
     */
    MSG_OK = 0x1,
    MSG_OK_WAIT, /* login, wait */
    MSG_OK_DONE, /* ready, proceed */
    MSG_REQ_RLEN, /* rundir length request */
    MSG_REQ_RDATA, /* rundir string request + how much is left */
    MSG_DATA,
    MSG_START,
    /* sent by server on errors */
    MSG_ERR,

    MSG_TYPE_BITS = 4,
    MSG_TYPE_MASK = 0xF,
    MSG_DATA_BYTES = sizeof(unsigned int) - 1
};

#define MSG_ENCODE_AUX(v, tp) \
    (tp | (static_cast<unsigned int>(v) << MSG_TYPE_BITS))

#define MSG_ENCODE(v) MSG_ENCODE_AUX(v, MSG_DATA)
#define MSG_SBYTES(len) std::min(int(MSG_DATA_BYTES), int(len))

#endif

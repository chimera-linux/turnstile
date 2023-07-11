/* defines the simple protocol between the daemon and the PAM module
 *
 * Copyright 2021 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef TURNSTILED_PROTOCOL_HH
#define TURNSTILED_PROTOCOL_HH

#include <sys/un.h>

#include "config.hh"

#ifndef RUN_PATH
#error "No RUN_PATH is defined"
#endif

#define DPAM_SERVICE "turnstiled"

#define SOCK_DIR DPAM_SERVICE
#define DAEMON_SOCK RUN_PATH "/" SOCK_DIR "/control.sock"

/* protocol messages
 *
 * this is a simple stream protocol; there are messages which fit within
 * a single byte, optionally followed by message-specific data bytes
 *
 * turnstiled is the server; the pam module is the client
 *
 * the client connects to DAEMON_SOCK
 *
 * from there, the following sequence happens:
 *
 * CLIENT: sends MSG_START, followed by uid (unsigned int), and enters a
 *         message loop (state machine)
 * SERVER: if service manager for the user is already running, responds
 *         with MSG_OK_DONE followed by a bool specifying whether the
 *         session bus address should be exported; else initiates startup
 *         and responds with MSG_OK_WAIT
 * CLIENT: if MSG_OK_WAIT was received, waits for another message
 * SERVER: once service manager starts, MSG_OK_DONE is sent (followed by
 *         the bool)
 * CLIENT: sends MSG_REQ_DATA
 * SERVER: responds with MSG_DATA, followed by rundir length (uint16_t),
 *         a bool specifying whether rundir should be set, and the rundir
 *         string itself
 * CLIENT: finishes startup, exports XDG_RUNTIME_DIR if needed as well
 *         as DBUS_SESSION_BUS_ADDRESS, and everything is done
 */

/* byte-sized message identifiers */
enum {
    MSG_OK_WAIT = 0x1, /* login, wait */
    MSG_OK_DONE, /* ready, proceed */
    MSG_REQ_DATA, /* session data request */
    MSG_DATA,
    MSG_START,
    /* sent by server on errors */
    MSG_ERR,
};

#endif

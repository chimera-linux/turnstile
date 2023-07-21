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
 *         with MSG_OK_DONE; else initiates startup and responds MSG_OK_WAIT
 * CLIENT: if MSG_OK_WAIT was received, waits for another message
 * SERVER: once service manager starts, MSG_OK_DONE is sent
 * CLIENT: sends MSG_REQ_ENV
 * SERVER: responds with MSG_ENV, followed by length of the environment
 *         block (unsigned int) followed by the environment data, which
 *         is a sequence of null-terminated strings
 * CLIENT: finishes startup, exports each variable in the received env
 *         block and finalizes session
 */

/* byte-sized message identifiers */
enum {
    MSG_OK_WAIT = 0x1, /* login, wait */
    MSG_OK_DONE, /* ready, proceed */
    MSG_REQ_ENV, /* session environment request */
    MSG_ENV,
    MSG_START,
    /* sent by server on errors */
    MSG_ERR,
};

#endif

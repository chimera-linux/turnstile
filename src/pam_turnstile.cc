/* pam_turnstile: the client part of turnstiled
 *
 * it connects to its socket and requests logins/logouts,
 * communicating over a rudimentary protocol
 *
 * the PAM session opens a persistent connection, which also
 * takes care of tracking when a session needs ending on the
 * daemon side (once all connections are gone)
 *
 * Copyright 2021 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include <pwd.h>
#include <endian.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>

#include "protocol.hh"

#define PAMAPI __attribute__((visibility ("default")))

static void free_sock(pam_handle_t *, void *data, int) {
    int sock = *static_cast<int *>(data);
    if (sock != -1) {
        close(sock);
    }
    free(data);
}

static bool open_session(
    pam_handle_t *pamh, unsigned int &uid, unsigned int &orlen,
    char *orbuf, bool &set_rundir, bool &set_dbus
) {
    int *sock = static_cast<int *>(std::malloc(sizeof(int)));
    if (!sock) {
        return false;
    }

    /* blocking socket and a simple protocol */
    *sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (*sock == -1) {
        return false;
    }

    /* associate the socket with the session */
    if (pam_set_data(
        pamh, "pam_turnstile_session", sock, free_sock
    ) != PAM_SUCCESS) {
        return false;
    }

    sockaddr_un saddr;
    std::memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    std::memcpy(saddr.sun_path, DAEMON_SOCK, sizeof(DAEMON_SOCK));

    char const *puser;
    passwd *pwd;
    int ret, rlen;

    auto send_msg = [sock](unsigned int msg) {
        if (write(*sock, &msg, sizeof(msg)) < 0) {
            return false;
        }
        return true;
    };

    if (pam_get_user(pamh, &puser, nullptr) != PAM_SUCCESS) {
        goto err;
    }

    pwd = getpwnam(puser);
    if (!pwd) {
        goto err;
    }
    uid = pwd->pw_uid;

    if (connect(
        *sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)
    ) < 0) {
        goto err;
    }

    if (!send_msg(MSG_ENCODE_AUX(pwd->pw_uid, MSG_START))) {
        goto err;
    }
    /* main message loop */
    {
        unsigned int msg;
        unsigned int state = 0;
        bool got_rlen = false;
        char *rbuf = orbuf;

        for (;;) {
            ret = read(*sock, &msg, sizeof(msg));
            if (ret < 0) {
                goto err;
            }
            switch (state) {
                case 0:
                case MSG_OK_WAIT:
                    /* if started, get the rundir back; else block
                     *
                     * if we previously waited and now got another message,
                     * it means either an error or that the system is now
                     * fully ready
                     */
                    if ((msg & MSG_TYPE_MASK) == MSG_OK_DONE) {
                        state = msg & MSG_TYPE_MASK;
                        set_dbus = !!(msg >> MSG_TYPE_BITS);
                        if (!send_msg(MSG_REQ_RLEN)) {
                            goto err;
                        }
                        continue;
                    } else if ((state == 0) && (msg == MSG_OK_WAIT)) {
                        state = msg;
                        continue;
                    }
                    /* bad message */
                    goto err;
                case MSG_OK_DONE: {
                    if ((msg & MSG_TYPE_MASK) != MSG_DATA) {
                        goto err;
                    }
                    /* after MSG_OK_DONE, we should receive the runtime dir
                     * length first; if zero, it means we are completely done
                     */
                    msg >>= MSG_TYPE_BITS;
                    if (!got_rlen) {
                        if (msg == 0) {
                            orlen = 0;
                            return true;
                        } else if (msg > DIRLEN_MAX) {
                            set_rundir = true;
                            msg -= DIRLEN_MAX;
                            if (msg > DIRLEN_MAX) {
                                goto err;
                            }
                        }
                        got_rlen = true;
                        rlen = int(msg);
                        orlen = msg;
                        if (!send_msg(MSG_ENCODE_AUX(rlen, MSG_REQ_RDATA))) {
                            goto err;
                        }
                        continue;
                    }
                    /* we are receiving the string... */
                    int pkts = MSG_SBYTES(rlen);
                    msg = htole32(msg);
                    std::memcpy(rbuf, &msg, pkts);
                    rbuf += pkts;
                    rlen -= pkts;
                    if (rlen == 0) {
                        /* we have received the whole thing, terminate */
                        *rbuf = '\0';
                        return true;
                    }
                    if (!send_msg(MSG_ENCODE_AUX(rlen, MSG_REQ_RDATA))) {
                        goto err;
                    }
                    /* keep receiving pieces */
                    continue;
                }
                default:
                    goto err;
            }
        }
    }

    return true;

err:
    close(*sock);
    *sock = -1;
    return false;
}

/* this may get used later for something */
static int open_session_turnstiled(pam_handle_t *) {
    return PAM_SUCCESS;
}

extern "C" PAMAPI int pam_sm_open_session(
    pam_handle_t *pamh, int, int argc, char const **argv
) {
    unsigned int uid, rlen = 0;
    bool set_rundir = false, set_dbus = false;
    /* potential rundir we are managing */
    char rdir[DIRLEN_MAX + 1];
    if (argc > 0) {
        if ((argc == 1) && !std::strcmp(argv[0], DPAM_SERVICE)) {
            return open_session_turnstiled(pamh);
        }
        pam_syslog(pamh, LOG_ERR, "Invalid module arguments");
        return PAM_SESSION_ERR;
    }
    if (!open_session(pamh, uid, rlen, rdir, set_rundir, set_dbus)) {
        return PAM_SESSION_ERR;
    }
    if (rlen) {
        char const dpfx[] = "DBUS_SESSION_BUS_ADDRESS=unix:path=";
        char buf[sizeof(rdir) + sizeof(dpfx) + 4];

        /* try exporting a dbus session bus variable */
        std::snprintf(buf, sizeof(buf), "%s%s/bus", dpfx, rdir);

        struct stat sbuf;
        if (
            set_dbus &&
            !lstat(strchr(buf, '/'), &sbuf) && S_ISSOCK(sbuf.st_mode)
        ) {
            if (pam_putenv(pamh, buf) != PAM_SUCCESS) {
                return PAM_SESSION_ERR;
            }
        }

        if (!set_rundir) {
            return PAM_SUCCESS;
        }

        std::snprintf(buf, sizeof(buf), "XDG_RUNTIME_DIR=%s", rdir);

        /* set rundir too if needed */
        if (pam_putenv(pamh, buf) != PAM_SUCCESS) {
            return PAM_SESSION_ERR;
        }
    }
    return PAM_SUCCESS;
}

extern "C" PAMAPI int pam_sm_close_session(
    pam_handle_t *pamh, int, int, char const **
) {
    void const *data;
    /* there is nothing we can do here */
    if (pam_get_data(pamh, "pam_turnstile_session", &data) != PAM_SUCCESS) {
        return PAM_SUCCESS;
    }
    int sock = *static_cast<int const *>(data);
    if (sock < 0) {
        return PAM_SUCCESS;
    }
    /* close the session */
    close(sock);
    return PAM_SUCCESS;
}

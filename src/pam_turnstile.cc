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
#include <cerrno>
#include <algorithm>

#include <pwd.h>
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
    pam_handle_t *pamh, unsigned int &uid, unsigned short &rlen,
    char *&orbuf, std::size_t dpfx, std::size_t dsfx,
    bool &set_rundir, bool &set_dbus
) {
    int *sock = static_cast<int *>(std::malloc(sizeof(int)));
    if (!sock) {
        return false;
    }

    /* blocking socket and a simple protocol */
    *sock = socket(AF_UNIX, SOCK_STREAM, 0);
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

    auto send_full = [sock](void *buf, size_t len) -> bool {
        auto *cbuf = static_cast<unsigned char *>(buf);
        while (len) {
            auto n = write(*sock, cbuf, len);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }
            cbuf += n;
            len -= n;
        }
        return true;
    };
    auto send_msg = [&send_full](unsigned char msg) -> bool {
        return send_full(&msg, sizeof(msg));
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

    if (!send_msg(MSG_START)) {
        goto err;
    }
    if (!send_full(&uid, sizeof(uid))) {
        goto err;
    }
    /* main message loop */
    {
        unsigned char msg;
        unsigned char state = 0;

        /* read an entire known-size buffer in one go */
        auto read_full = [sock](void *buf, size_t len) -> bool {
            auto *cbuf = static_cast<unsigned char *>(buf);
            while (len) {
                auto n = read(*sock, cbuf, len);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    return false;
                }
                cbuf += n;
                len -= n;
            }
            return true;
        };

        for (;;) {
            if (!read_full(&msg, sizeof(msg))) {
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
                    if (msg == MSG_OK_DONE) {
                        state = msg;
                        if (!read_full(&set_dbus, sizeof(set_dbus))) {
                            goto err;
                        }
                        if (!send_msg(MSG_REQ_DATA)) {
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
                    if (msg != MSG_DATA) {
                        goto err;
                    }
                    /* after MSG_OK_DONE, we should receive the runtime dir
                     * length first; if zero, it means we are completely done
                     */
                    if (!read_full(&rlen, sizeof(rlen))) {
                        goto err;
                    }
                    /* alloc tne buffer */
                    if (rlen) {
                        orbuf = static_cast<char *>(std::malloc(
                            rlen + dpfx + dsfx + 1
                        ));
                        if (!orbuf) {
                            goto err;
                        }
                    }
                    /* followed by a bool whether rundir should be set */
                    if (!read_full(&set_rundir, sizeof(set_rundir))) {
                        goto err;
                    }
                    /* followed by the string */
                    if (rlen && !read_full(orbuf + dpfx, rlen)) {
                        goto err;
                    }
                    orbuf[dpfx + rlen] = '\0';
                    return true;
                }
                default:
                    goto err;
            }
        }
    }

    return true;

err:
    std::free(orbuf);
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
    unsigned int uid;
    unsigned short rlen = 0;
    bool set_rundir = false, set_dbus = false;
    /* potential rundir we are managing */
    char *rdir = nullptr;
    /* prefix and suffix for the buffer */
    char const dpfx[] = "DBUS_SESSION_BUS_ADDRESS=unix:path=";
    char const rpfx[] = "XDG_RUNTIME_DIR=";
    char const dsfx[] = "/bus";
    /* dual purpose */
    if (argc > 0) {
        if ((argc == 1) && !std::strcmp(argv[0], DPAM_SERVICE)) {
            return open_session_turnstiled(pamh);
        }
        pam_syslog(pamh, LOG_ERR, "Invalid module arguments");
        return PAM_SESSION_ERR;
    }
    if (!open_session(
        pamh, uid, rlen, rdir, sizeof(dpfx) - 1, sizeof(dsfx) - 1,
        set_rundir, set_dbus
    )) {
        return PAM_SESSION_ERR;
    }
    if (rlen) {
        /* rdir path */
        char *rpath = rdir + sizeof(dpfx) - 1;
        /* write the prefix and suffix */
        std::memcpy(rdir, dpfx, sizeof(dpfx) - 1);
        std::memcpy(rpath + rlen, dsfx, sizeof(dsfx));

        /* try exporting a dbus session bus variable */
        struct stat sbuf;
        if (set_dbus && !lstat(rpath, &sbuf) && S_ISSOCK(sbuf.st_mode)) {
            if (pam_putenv(pamh, rdir) != PAM_SUCCESS) {
                std::free(rdir);
                return PAM_SESSION_ERR;
            }
        }

        if (!set_rundir) {
            std::free(rdir);
            return PAM_SUCCESS;
        }

        /* replace the prefix and strip /bus */
        std::memcpy(rpath - sizeof(rpfx) + 1, rpfx, sizeof(rpfx) - 1);
        rpath[rlen] = '\0';

        /* set rundir too if needed */
        if (pam_putenv(pamh, rpath - sizeof(rpfx) + 1) != PAM_SUCCESS) {
            std::free(rdir);
            return PAM_SESSION_ERR;
        }
        std::free(rdir);
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

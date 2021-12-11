/* pam_dinit_userservd: the client part of dinit-userservd
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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <security/pam_modules.h>

#include "protocol.hh"

#define PAMAPI __attribute__((visibility ("default")))

static void free_sock(pam_handle_t *, void *data, int) {
    int sock = *static_cast<int *>(data);
    if (sock != -1) {
        close(sock);
    }
    free(data);
}

static bool open_session(pam_handle_t *pamh, unsigned int &uid) {
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
        pamh, "pam_dinit_session", sock, free_sock
    ) != PAM_SUCCESS) {
        return false;
    }

    sockaddr_un saddr;
    std::memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    std::memcpy(saddr.sun_path, DAEMON_SOCK, sizeof(DAEMON_SOCK));

    char const *puser;
    char const *hdir;
    passwd *pwd;
    int ret, hlen;

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

    hdir = pam_getenv(pamh, "HOME");
    if (!hdir || !hdir[0]) {
        hdir = pwd->pw_dir;
    }
    if (!hdir || !hdir[0]) {
        goto err;
    }
    hlen = strlen(hdir);
    if (hlen > HDIRLEN_MAX) {
        goto err;
    }
    /* this is verified serverside too but bail out early if needed */
    if (struct stat s; stat(hdir, &s) || !S_ISDIR(s.st_mode)) {
        goto err;
    }

    if (connect(
        *sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)
    ) < 0) {
        goto err;
    }

    if (!send_msg(MSG_WELCOME)) {
        goto err;
    }
    /* main message loop */
    {
        unsigned int msg;
        unsigned int state = 0;
        bool sent_uid = false;
        bool sent_gid = false;
        bool sent_hlen = false;

        for (;;) {
            ret = read(*sock, &msg, sizeof(msg));
            if (ret < 0) {
                goto err;
            }
            switch (state) {
                case 0:
                    /* session not established yet */
                    if (msg != MSG_OK) {
                        goto err;
                    }
                    /* send uid */
                    if (!sent_uid) {
                        if (!send_msg(pwd->pw_uid)) {
                            goto err;
                        }
                        sent_uid = true;
                        break;
                    }
                    /* send gid */
                    if (!sent_gid) {
                        if (!send_msg(pwd->pw_gid)) {
                            goto err;
                        }
                        sent_gid = true;
                        break;
                    }
                    /* send homedir len */
                    if (!sent_hlen) {
                        if (!send_msg(hlen)) {
                            goto err;
                        }
                        sent_hlen = true;
                        break;
                    }
                    /* send a piece of homedir */
                    if (hlen) {
                        unsigned int pkt = 0;
                        auto psize = std::min(std::size_t(hlen), sizeof(pkt));
                        std::memcpy(&pkt, hdir, psize);
                        if (!send_msg(pkt)) {
                            goto err;
                        }
                        hdir += psize;
                        hlen -= psize;
                        break;
                    }
                    /* send clientside OK */
                    state = msg;
                    if (!send_msg(MSG_OK)) {
                        goto err;
                    }
                    break;
                case MSG_OK:
                    /* already fully started, just finish */
                    if (msg == MSG_OK_DONE) {
                        return true;
                    }
                    /* not yet fully started, block on another read */
                    if (msg == MSG_OK_WAIT) {
                        state = MSG_OK_WAIT;
                        continue;
                    }
                    /* bad message */
                    goto err;
                case MSG_OK_WAIT:
                    /* if we previously waited and now got another message,
                     * it means either an error or that the system is now
                     * fully ready
                     */
                    if (msg == MSG_OK_DONE) {
                        return true;
                    }
                    /* bad message */
                    goto err;
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

extern "C" PAMAPI int pam_sm_open_session(
    pam_handle_t *pamh, int, int, char const **
) {
    unsigned int uid;
    if (!open_session(pamh, uid)) {
        return PAM_SESSION_ERR;
    }
    /* try exporting a dbus session bus variable */
    char buf[512];
    std::snprintf(
        buf, sizeof(buf),
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%u/bus", uid
    );

    struct stat sbuf;
    if (!stat(strchr(buf, '/'), &sbuf) && S_ISSOCK(sbuf.st_mode)) {
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
    if (pam_get_data(pamh, "pam_dinit_session", &data) != PAM_SUCCESS) {
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

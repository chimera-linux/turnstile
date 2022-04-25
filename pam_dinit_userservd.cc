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
#include <security/pam_misc.h>

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
    pam_handle_t *pamh, unsigned int &uid, int argc, char const **argv,
    unsigned int &orlen, char *orbuf, bool &set_rundir
) {
    int *sock = static_cast<int *>(std::malloc(sizeof(int)));
    if (!sock) {
        return false;
    }

#if 0
    /* FIXME: this is problematic with gdm somehow, figure out why */
    bool do_rundir = true;

    /* overrides */
    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "norundir")) {
            do_rundir = false;
        }
    }
#else
    bool do_rundir = false;
#endif

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
    char const *rdir;
    passwd *pwd;
    int ret, hlen, rlen;

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
    if (hlen > DIRLEN_MAX) {
        goto err;
    }
    /* this is verified serverside too but bail out early if needed */
    if (struct stat s; stat(hdir, &s) || !S_ISDIR(s.st_mode)) {
        goto err;
    }

    /* the other runtime dir manager is expected to ensure that the
     * rundir actually exists by this point (logind does ensure it)
     */
    rdir = pam_getenv(pamh, "XDG_RUNTIME_DIR");
    if (!rdir) {
        rdir = "";
    }
    rlen = strlen(rdir);
    if (rlen > DIRLEN_MAX) {
        goto err;
    } else if (rlen == 0) {
        set_rundir = do_rundir;
    }

    if (connect(
        *sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)
    ) < 0) {
        goto err;
    }

    if (!send_msg(MSG_START)) {
        goto err;
    }
    /* main message loop */
    {
        unsigned int msg;
        unsigned int state = 0;
        bool sent_uid = false;
        bool sent_gid = false;
        bool sent_hlen = false;
        bool sent_rlen = false;
        bool got_rlen = false;
        char *rbuf = orbuf;

        auto send_strpkt = [&send_msg](char const *&sdir, int &slen) {
            unsigned int pkt = 0;
            auto psize = MSG_SBYTES(slen);
            std::memcpy(&pkt, sdir, psize);
            pkt <<= MSG_TYPE_BITS;
            pkt |= MSG_DATA;
            if (!send_msg(pkt)) {
                return false;
            }
            sdir += psize;
            slen -= psize;
            return true;
        };

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
                        if (!send_msg(MSG_ENCODE(pwd->pw_uid))) {
                            goto err;
                        }
                        sent_uid = true;
                        break;
                    }
                    /* send gid */
                    if (!sent_gid) {
                        if (!send_msg(MSG_ENCODE(pwd->pw_gid))) {
                            goto err;
                        }
                        sent_gid = true;
                        break;
                    }
                    /* send homedir len */
                    if (!sent_hlen) {
                        if (!send_msg(MSG_ENCODE(hlen))) {
                            goto err;
                        }
                        sent_hlen = true;
                        break;
                    }
                    /* send a piece of homedir */
                    if (hlen) {
                        if (!send_strpkt(hdir, hlen)) {
                            goto err;
                        }
                        break;
                    }
                    /* send rundir len */
                    if (!sent_rlen) {
                        auto srlen = rlen;
                        if (!srlen && !do_rundir) {
                            srlen = DIRLEN_MAX + 1;
                        }
                        if (!send_msg(MSG_ENCODE(srlen))) {
                            goto err;
                        }
                        sent_rlen = true;
                        break;
                    }
                    /* send a piece of rundir */
                    if (rlen) {
                        if (!send_strpkt(rdir, rlen)) {
                            goto err;
                        }
                        break;
                    }
                    /* send clientside OK */
                    state = msg;
                    if (!send_msg(MSG_OK)) {
                        goto err;
                    }
                    break;
                case MSG_OK:
                    /* if started, get the rundir back; else block */
                    if ((msg == MSG_OK_DONE) || (msg == MSG_OK_WAIT)) {
                        state = msg;
                        if ((msg == MSG_OK_DONE) && !send_msg(MSG_REQ_RLEN)) {
                            goto err;
                        }
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
                        state = msg;
                        if (!send_msg(MSG_REQ_RLEN)) {
                            goto err;
                        }
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
                            goto err;
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

extern "C" PAMAPI int pam_sm_open_session(
    pam_handle_t *pamh, int, int argc, char const **argv
) {
    unsigned int uid, rlen = 0;
    bool set_rundir = false;
    /* potential rundir we are managing */
    char rdir[DIRLEN_MAX + 1];
    if (!open_session(pamh, uid, argc, argv, rlen, rdir, set_rundir)) {
        return PAM_SESSION_ERR;
    }
    if (rlen) {
        char const dpfx[] = "DBUS_SESSION_BUS_ADDRESS=unix:path=";
        char buf[sizeof(rdir) + sizeof(dpfx) + 4];

        /* try exporting a dbus session bus variable */
        std::snprintf(buf, sizeof(buf), "%s%s/bus", dpfx, rdir);

        struct stat sbuf;
        if (!lstat(strchr(buf, '/'), &sbuf) && S_ISSOCK(sbuf.st_mode)) {
            if (pam_putenv(pamh, buf) != PAM_SUCCESS) {
                return PAM_SESSION_ERR;
            }
        }

        if (!set_rundir) {
            return PAM_SUCCESS;
        }

        /* set rundir too if needed */
        if (pam_misc_setenv(pamh, "XDG_RUNTIME_DIR", rdir, 1) != PAM_SUCCESS) {
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

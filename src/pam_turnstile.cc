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
#include <cctype>
#include <cerrno>
#include <algorithm>

#include <pwd.h>
#include <unistd.h>
#include <syslog.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>

#include "protocol.hh"
#include "utils.hh"

#define PAMAPI __attribute__((visibility ("default")))

static void free_sock(pam_handle_t *, void *data, int) {
    int sock = *static_cast<int *>(data);
    if (sock != -1) {
        close(sock);
    }
    free(data);
}

static bool open_session(
    pam_handle_t *pamh,
    unsigned int uid,
    char const *service,
    char const *stype,
    char const *sclass,
    char const *sdesktop,
    char const *sseat,
    char const *tty,
    char const *display,
    char const *ruser,
    char const *rhost,
    unsigned long vtnr,
    bool remote,
    unsigned int &elen,
    char *&ebuf,
    bool debug
) {
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "open session");
    }

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

    auto send_full = [sock](void const *buf, std::size_t len) -> bool {
        auto *cbuf = static_cast<unsigned char const *>(buf);
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
    auto send_str = [&send_full](char const *str) -> bool {
        std::size_t slen = str ? strlen(str) : 0;
        if (!send_full(&slen, sizeof(slen))) {
            return false;
        }
        return send_full(str, slen);
    };

    if (connect(
        *sock, reinterpret_cast<sockaddr const *>(&saddr), sizeof(saddr)
    ) < 0) {
        goto err;
    }

    if (!send_msg(MSG_START)) {
        goto err;
    }
    /* send all the arguments */
    if (!send_full(&uid, sizeof(uid))) {
        goto err;
    }
    if (!send_full(&vtnr, sizeof(vtnr))) {
        goto err;
    }
    if (!send_full(&remote, sizeof(remote))) {
        goto err;
    }
    if (!send_str(service)) {
        goto err;
    }
    if (!send_str(stype)) {
        goto err;
    }
    if (!send_str(sclass)) {
        goto err;
    }
    if (!send_str(sdesktop)) {
        goto err;
    }
    if (!send_str(sseat)) {
        goto err;
    }
    if (!send_str(tty)) {
        goto err;
    }
    if (!send_str(display)) {
        goto err;
    }
    if (!send_str(ruser)) {
        goto err;
    }
    if (!send_str(rhost)) {
        goto err;
    }

    /* main message loop */
    {
        unsigned char msg;
        unsigned char state = 0;

        /* read an entire known-size buffer in one go */
        auto recv_full = [sock](void *buf, size_t len) -> bool {
            auto *cbuf = static_cast<unsigned char *>(buf);
            while (len) {
                auto n = recv(*sock, cbuf, len, 0);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    return false;
                } else if (n == 0) {
                    /* eof; connection closed by peer */
                    return false;
                }
                cbuf += n;
                len -= n;
            }
            return true;
        };

        for (;;) {
            if (!recv_full(&msg, sizeof(msg))) {
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
                        if (!send_msg(MSG_REQ_ENV)) {
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
                    if (msg != MSG_ENV) {
                        goto err;
                    }
                    /* after MSG_OK_DONE, we should receive the environment
                     * length first; if zero, it means we are completely done
                     */
                    if (!recv_full(&elen, sizeof(elen))) {
                        goto err;
                    }
                    /* alloc the buffer */
                    if (elen) {
                        ebuf = static_cast<char *>(std::malloc(elen));
                        if (!ebuf) {
                            goto err;
                        }
                        /* followed by the environment block */
                        if (!recv_full(ebuf, elen)) {
                            goto err;
                        }
                    }
                    return true;
                }
                default:
                    goto err;
            }
        }
    }

    return true;

err:
    std::free(ebuf);
    close(*sock);
    *sock = -1;
    return false;
}

/* this may get used later for something */
static int open_session_turnstiled(pam_handle_t *pamh, bool debug) {
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "pam_turnstile init session");
    }
    return PAM_SUCCESS;
}

static unsigned long get_x_vtnr(char const *display) {
    /* get the server number, drop if non-local */
    if (display[0] != ':') {
        return 0;
    }
    char *endp = nullptr;
    unsigned long xnum = std::strtoul(display + 1, &endp, 10);
    if (endp && *endp) {
        return 0;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    sockaddr_un saddr;
    std::memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    /* try abstract socket first, linux only but harmless */
    std::snprintf(
        saddr.sun_path, sizeof(saddr.sun_path), "@/tmp/.X11-unix/X%lu", xnum
    );

    auto *sa = reinterpret_cast<sockaddr const *>(&saddr);
    if (connect(sock, sa, sizeof(saddr)) < 0) {
        /* try non-abstract socket */
        std::memmove(
            saddr.sun_path, saddr.sun_path + 1, sizeof(saddr.sun_path ) - 1
        );
        /* if that fails too, drop */
        if (connect(sock, sa, sizeof(saddr)) < 0) {
            close(sock);
            return 0;
        }
    }

    /* the xserver PID */
    pid_t xpid = -1;
    get_peer_cred(sock, nullptr, nullptr, &xpid);

    close(sock);

    if (xpid < 0) {
        return 0;
    }

    return get_pid_vtnr(xpid);
}

static void parse_args(
    pam_handle_t *pamh, int argc, char const **argv, bool &debug, bool &sess,
    char const **cl, char const **dtop, char const **type
) {
    for (int i = 0; i < argc; ++i) {
        /* is in-session invocation */
        if (!std::strcmp(argv[i], DPAM_SERVICE)) {
            sess = true;
            continue;
        }
        /* debug */
        if (!std::strcmp(argv[i], "debug")) {
            debug = true;
            continue;
        }
        /* provided class */
        if (!std::strncmp(argv[i], "class=", 6)) {
            if (cl) {
                *cl = argv[i] + 6;
            }
            continue;
        }
        /* provided desktop */
        if (!std::strncmp(argv[i], "desktop=", 8)) {
            if (dtop) {
                *dtop = argv[i] + 8;
            }
            continue;
        }
        /* provided type */
        if (!std::strncmp(argv[i], "type=", 5)) {
            if (type) {
                *type = argv[i] + 5;
            }
            continue;
        }
        /* unknown */
        pam_syslog(pamh, LOG_WARNING, "unknown parameter '%s'", argv[i]);
    }
}

static char const *getenv_pam(pam_handle_t *pamh, char const *key) {
    auto *v = pam_getenv(pamh, key);
    if (v && *v) {
        return v;
    }
    v = getenv(key);
    if (v && *v) {
        return v;
    }
    return nullptr;
}

extern "C" PAMAPI int pam_sm_open_session(
    pam_handle_t *pamh, int, int argc, char const **argv
) {
    /* optional args */
    bool debug = false, in_sess = false;
    char const *pclass = nullptr;
    char const *pdesktop = nullptr;
    char const *ptype = nullptr;
    /* parse the args */
    parse_args(pamh, argc, argv, debug, in_sess, &pclass, &pdesktop, &ptype);

    /* debug */
    if (debug) {
        pam_syslog(pamh, LOG_DEBUG, "pam_turnstile init");
    }

    /* dual purpose */
    if (in_sess) {
        return open_session_turnstiled(pamh, debug);
    }

    /* obtain the user */
    char const *puser = nullptr;
    if (pam_get_user(pamh, &puser, nullptr) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "could not get PAM user");
        return PAM_SESSION_ERR;
    }
    passwd *pwd = getpwnam(puser);
    if (!pwd) {
        pam_syslog(pamh, LOG_ERR, "getpwnam failed (%s)", strerror(errno));
        return PAM_SESSION_ERR;
    }

    /* get some pam session data */
    auto get_pamitem = [pamh](int itype, char const *name, char const **item) {
        void const *itemv = nullptr;
        auto r = pam_get_item(pamh, itype, &itemv);
        if ((r == PAM_SUCCESS) || (r == PAM_BAD_ITEM)) {
            if (itemv) {
                *item = static_cast<char const *>(itemv);
            }
            return true;
        }
        pam_syslog(
            pamh, LOG_ERR, "could not get PAM item: %s (%s)",
            name, pam_strerror(pamh, r)
        );
        return false;
    };
    char const *service = nullptr;
    if (!get_pamitem(PAM_SERVICE, "PAM_SERVICE", &service)) {
        return PAM_SESSION_ERR;
    }
    char const *display = nullptr;
    if (!get_pamitem(PAM_XDISPLAY, "PAM_XDISPLAY", &display)) {
        return PAM_SESSION_ERR;
    }
    char const *tty = nullptr;
    if (!get_pamitem(PAM_TTY, "PAM_TTY", &tty)) {
        return PAM_SESSION_ERR;
    }
    char const *remote_user = nullptr;
    if (!get_pamitem(PAM_RUSER, "PAM_RUSER", &remote_user)) {
        return PAM_SESSION_ERR;
    }
    char const *remote_host = nullptr;
    if (!get_pamitem(PAM_RHOST, "PAM_RHOST", &remote_host)) {
        return PAM_SESSION_ERR;
    }

    /* try obtain from environment */
    char const *xclass = getenv_pam(pamh, "XDG_SESSION_CLASS");
    if (!xclass) {
        xclass = pclass;
    }
    char const *xdesktop = getenv_pam(pamh, "XDG_SESSION_DESKTOP");
    if (!xdesktop) {
        xdesktop = pdesktop;
    }
    char const *xtype = getenv_pam(pamh, "XDG_SESSION_TYPE");
    if (!xtype) {
        xtype = ptype;
    }
    char const *xseat = getenv_pam(pamh, "XDG_SEAT");
    char const *xvtnr = getenv_pam(pamh, "XDG_VTNR");

    /* this more or less mimics logind for compatibility */
    if (tty) {
        if (std::strchr(tty, ':')) {
            /* X11 display */
            if (!display || !*display) {
                display = tty;
            }
            tty = nullptr;
        } else if (!std::strcmp(tty, "cron")) {
            xtype = "unspecified";
            xclass = "background";
            tty = nullptr;
        } else if (!std::strcmp(tty, "ssh")) {
            xtype = "tty";
            xclass = "user";
            tty = nullptr;
        } else if (!std::strncmp(tty, "/dev/", 5)) {
            tty += 5;
        }
    }

    unsigned long vtnr = 0;
    if (xvtnr) {
        char *endp = nullptr;
        vtnr = std::strtoul(xvtnr, &endp, 10);
        if (endp && *endp) {
            vtnr = 0;
        }
    }

    /* get vtnr from X display if possible */
    if (display && *display && !vtnr) {
        if (!xseat || !*xseat) {
            /* assign default seat for X sessions if not set */
            xseat = "seat0";
        }
        vtnr = get_x_vtnr(display);
    }

    /* get vtnr from tty number if possible */
    if (tty && !std::strncmp(tty, "tty", 3) && !vtnr) {
        char *endp = nullptr;
        vtnr = strtoul(tty + 3, &endp, 10);
        if (endp && *endp) {
            /* tty != "ttyN" */
            vtnr = 0;
        }
        if (vtnr && (!xseat || !*xseat)) {
            /* assign default seat for console sessions if not set */
            xseat = "seat0";
        }
    }

    /* other-seat sessions cannot have vtnr */
    if (xseat && std::strcmp(xseat, "seat0") && vtnr) {
        vtnr = 0;
    }

    if (!xtype || !*xtype) {
        xtype = (display && *display) ? "x11" : (
            (tty && *tty) ? "tty" : "unspecified"
        );
    }
    if (!xclass || !*xclass) {
        xclass = !std::strcmp(xtype, "unspecified") ? "background" : "user";
    }

    bool remote = false;
    if (remote_host && *remote_host) {
        char buf[32];
        auto hlen = std::strlen(remote_host);
        if (hlen >= sizeof(buf)) {
            std::memcpy(buf, remote_host + hlen - sizeof(buf) + 1, sizeof(buf));
            hlen = sizeof(buf) - 1;
        } else {
            std::memcpy(buf, remote_host, hlen + 1);
        }
        /* strip trailing dot */
        if (buf[hlen - 1] == '.') {
            buf[hlen - 1] = '\0';
        }
        char *rdot = std::strrchr(buf, '.');
        if (rdot && !strcasecmp(rdot + 1, "localdomain")) {
            *rdot = '\0';
        }
        if (!strcasecmp(buf, "localhost")) {
            remote = true;
        } else {
            rdot = std::strrchr(buf, '.');
            if (rdot && !strcasecmp(rdot + 1, "localhost")) {
                remote = true;
            }
        }
    }

    char *ebuf = nullptr;
    unsigned int elen = 0;

    if (!open_session(
        pamh,
        pwd->pw_uid,
        service,
        xtype,
        xclass,
        xdesktop,
        xseat,
        tty,
        display,
        remote_user,
        remote_host,
        vtnr,
        remote,
        /* output and misc parameters */
        elen,
        ebuf,
        debug
    )) {
        return PAM_SESSION_ERR;
    }

    for (char *ecur = ebuf; elen;) {
        if (pam_putenv(pamh, ecur) != PAM_SUCCESS) {
            std::free(ebuf);
            return PAM_SESSION_ERR;
        }
        /* includes null terminator */
        auto clen = std::strlen(ecur) + 1;
        if (elen >= clen) {
            ecur += clen;
            elen -= clen;
        } else {
            std::free(ebuf);
            return PAM_SESSION_ERR;
        }
    }
    std::free(ebuf);

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

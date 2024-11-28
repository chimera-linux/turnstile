/* turnstiled: handle incoming login requests and start (or
 *             stop) service manager instances as necessary
 *
 * the daemon should never exit under "normal" circumstances
 *
 * Copyright 2021 q66 <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* accept4 */
#endif

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cassert>
#include <climits>
#include <cctype>
#include <algorithm>
#include <new>

#include <pwd.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "turnstiled.hh"
#include "utils.hh"

#ifndef CONF_PATH
#error "No CONF_PATH is defined"
#endif

/* we accept connections from non-root
 *
 * this relies on non-portable credentials checking,
 * so it must be implemented for every system separately
 *
 * it would be nice to get this implemented on other systems
 */
#define CSOCK_MODE 0666

#define DEFAULT_CFG_PATH CONF_PATH "/turnstiled.conf"

/* when stopping service manager, we first do a SIGTERM and set up this
 * timeout, if it fails to quit within that period, we issue a SIGKILL
 * and try this timeout again, after that it is considered unrecoverable
 */
static constexpr std::time_t kill_timeout = 60;

/* global */
cfg_data *cdata = nullptr;

/* the file descriptor for the base directory */
static int dirfd_base = -1;
/* the file descriptor for the users directory */
static int dirfd_users = -1;
/* the file descriptor for the sessions directory */
static int dirfd_sessions = -1;

static bool write_udata(login const &lgn);
static bool write_sdata(session const &sess);
static void drop_udata(login const &lgn);
static void drop_sdata(session const &sess);

login::login() {
    timer_sev.sigev_notify = SIGEV_SIGNAL;
    timer_sev.sigev_signo = SIGALRM;
    timer_sev.sigev_value.sival_ptr = this;
    srvstr.reserve(256);
}

void login::remove_sdir() {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u", this->uid);
    unlinkat(dirfd_base, buf, AT_REMOVEDIR);
    /* just in case, we know this is a named pipe */
    unlinkat(this->dirfd, "ready", 0);
    dir_clear_contents(this->dirfd);
    this->dirfd = -1;
}

bool login::arm_timer(std::time_t timeout) {
    if (timer_create(CLOCK_MONOTONIC, &timer_sev, &timer) < 0) {
        print_err("timer: timer_create failed (%s)", strerror(errno));
        return false;
    }
    itimerspec tval{};
    tval.it_value.tv_sec = timeout;
    if (timer_settime(timer, 0, &tval, nullptr) < 0) {
        print_err("timer: timer_settime failed (%s)", strerror(errno));
        timer_delete(timer);
        return false;
    }
    timer_armed = true;
    return true;
}

void login::disarm_timer() {
    if (!timer_armed) {
        return;
    }
    timer_delete(timer);
    timer_armed = false;
}

static std::vector<login> logins;

/* file descriptors for poll */
static std::vector<pollfd> fds;
/* connections pending a session */
static std::vector<int> pending_sess;
/* number of pipes we are polling on */
static std::size_t npipes = 0;
/* control IPC socket */
static int ctl_sock;
/* signal self-pipe */
static int sigpipe[2] = {-1, -1};
/* session counter, each session gets a new number (i.e. numbers never
 * get reused even if the session of that number dies); session numbers
 * are unique even across logins
 */
static unsigned long idbase = 0;

/* start the service manager instance for a login */
static bool srv_start(login &lgn) {
    /* prepare some strings */
    char uidbuf[32];
    std::snprintf(uidbuf, sizeof(uidbuf), "%u", lgn.uid);
    /* mark as waiting */
    lgn.srv_wait = true;
    /* set up login dir */
    print_dbg("srv: create login dir for %u", lgn.uid);
    /* make the directory itself */
    lgn.dirfd = dir_make_at(dirfd_base, uidbuf, 0700);
    if (lgn.dirfd < 0) {
        print_err(
            "srv: failed to make login dir for %u (%s)",
            lgn.uid, strerror(errno)
        );
        return false;
    }
    /* ensure it's owned by the user */
    if (fchownat(
        dirfd_base, uidbuf, lgn.uid, lgn.gid, AT_SYMLINK_NOFOLLOW
    ) || fcntl(lgn.dirfd, F_SETFD, FD_CLOEXEC)) {
        print_err(
            "srv: login dir setup failed for %u (%s)",
            lgn.uid, strerror(errno)
        );
        lgn.remove_sdir();
        return false;
    }
    print_dbg("srv: create readiness pipe");
    unlinkat(lgn.dirfd, "ready", 0);
    if (mkfifoat(lgn.dirfd, "ready", 0700) < 0) {
        print_err("srv: failed to make ready pipe (%s)", strerror(errno));
        return false;
    }
    /* ensure it's owned by user too, and open in nonblocking mode */
    if (fchownat(
        lgn.dirfd, "ready", lgn.uid, lgn.gid, AT_SYMLINK_NOFOLLOW
    ) || ((lgn.userpipe = openat(
        lgn.dirfd, "ready", O_NONBLOCK | O_RDONLY
    )) < 0)) {
        print_err(
            "srv: failed to set up ready pipe (%s)", strerror(errno)
        );
        unlinkat(lgn.dirfd, "ready", 0);
        lgn.remove_sdir();
        return false;
    }
    /* set up the timer, issue SIGLARM when it fires */
    print_dbg("srv: timer set");
    if (cdata->login_timeout > 0) {
        if (!lgn.arm_timer(cdata->login_timeout)) {
            return false;
        }
    } else {
        print_dbg("srv: no timeout");
    }
    /* launch service manager */
    print_dbg("srv: launch");
    auto pid = fork();
    if (pid == 0) {
        /* reset signals from parent */
        struct sigaction sa{};
        sa.sa_handler = SIG_DFL;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, nullptr);
        sigaction(SIGALRM, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT, &sa, nullptr);
        /* close some descriptors, these can be reused */
        close(lgn.userpipe);
        close(dirfd_base);
        close(sigpipe[0]);
        close(sigpipe[1]);
        /* and run the login */
        bool has_backend = !cdata->disable && (
            (lgn.uid != 0) || cdata->root_session
        );
        srv_child(
            lgn,
            has_backend ? cdata->backend.data() : nullptr,
            cdata->manage_rdir
        );
        exit(1);
    } else if (pid < 0) {
        print_err("srv: fork failed (%s)", strerror(errno));
        return false;
    }
    /* close the write end on our side */
    lgn.srv_pending = false;
    lgn.srv_pid = pid;
    if (lgn.userpipe < 0) {
        /* disabled */
        return srv_boot(lgn, nullptr);
    }
    /* otherwise queue the pipe */
    lgn.pipe_queued = true;
    return true;
}

static session *get_session(int fd) {
    for (auto &lgn: logins) {
        for (auto &sess: lgn.sessions) {
            if (fd == sess.fd) {
                return &sess;
            }
        }
    }
    print_dbg("msg: no session for %d", fd);
    return nullptr;
}

static login *login_populate(unsigned int uid) {
    login *lgn = nullptr;
    for (auto &lgnr: logins) {
        if (lgnr.uid == uid) {
            if (!lgnr.repopulate) {
                print_dbg("msg: using existing login %u", uid);
                return &lgnr;
            }
            lgn = &lgnr;
            break;
        }
    }
    auto *pwd = getpwuid(uid);
    if (!pwd) {
        print_err("msg: failed to get pwd for %u (%s)", uid, strerror(errno));
        return nullptr;
    }
    if (pwd->pw_dir[0] != '/') {
        print_err(
            "msg: homedir of %s (%u) is not absolute (%s)", pwd->pw_name,
            uid, pwd->pw_dir
        );
        return nullptr;
    }
    if (lgn) {
        print_dbg("msg: repopulate login %u", pwd->pw_uid);
    } else {
        print_dbg("msg: init login %u", pwd->pw_uid);
        lgn = &logins.emplace_back();
    }
    /* fill in initial login details */
    lgn->uid = pwd->pw_uid;
    lgn->gid = pwd->pw_gid;
    lgn->username = pwd->pw_name;
    lgn->homedir = pwd->pw_dir;
    lgn->shell = pwd->pw_shell;
    lgn->rundir.clear();
    /* somewhat heuristical */
    lgn->rundir.reserve(cdata->rdir_path.size() + 8);
    cfg_expand_rundir(lgn->rundir, cdata->rdir_path.data(), lgn->uid, lgn->gid);
    lgn->manage_rdir = cdata->manage_rdir && !lgn->rundir.empty();
    lgn->repopulate = false;
    return lgn;
}

static session *handle_session_new(int fd, unsigned int uid) {
    /* check for credential mismatch */
    uid_t puid;
    pid_t lpid;
    if (!get_peer_cred(fd, &puid, nullptr, &lpid)) {
        print_dbg("msg: could not get peer credentials");
        return nullptr;
    }
    if (puid != 0) {
        print_dbg("msg: can't set up session (permission denied)");
        return nullptr;
    }
    /* acknowledge the login */
    print_dbg("msg: welcome %u", uid);
    auto *lgn = login_populate(uid);
    if (!lgn) {
        return nullptr;
    }
    /* check the sessions */
    for (auto &sess: lgn->sessions) {
        if (sess.fd == fd) {
            print_dbg("msg: already have session for %u/%d", lgn->uid, fd);
            return nullptr;
        }
    }
    print_dbg("msg: new session for %u/%d", lgn->uid, fd);
    /* create a new session */
    auto &sess = lgn->sessions.emplace_back();
    sess.fd = fd;
    sess.id = ++idbase;
    sess.lgn = lgn;
    sess.lpid = lpid;
    /* initial message */
    sess.needed = 1;
    /* reply */
    return &sess;
}

static bool write_udata(login const &lgn) {
    char uname[32], tmpname[32];
    std::snprintf(tmpname, sizeof(tmpname), "%u.tmp", lgn.uid);
    std::snprintf(uname, sizeof(uname), "%u", lgn.uid);
    int omask = umask(0);
    int lgnfd = openat(
        dirfd_users, tmpname, O_CREAT | O_TRUNC | O_WRONLY, 0644
    );
    if (lgnfd < 0) {
        print_err("msg: user tmpfile failed (%s)", strerror(errno));
        umask(omask);
        return false;
    }
    umask(omask);
    auto *lgnf = fdopen(lgnfd, "w");
    if (!lgnf) {
        print_err("msg: user fdopen failed (%s)", strerror(errno));
        close(lgnfd);
        return false;
    }
    std::fprintf(
        lgnf,
        "NAME=%s\n"
        "RUNTIME=%s\n",
        lgn.username.data(),
        lgn.rundir.data()
    );
    std::fprintf(lgnf, "SESSIONS=");
    bool first = true;
    for (auto &s: lgn.sessions) {
        if (!first) {
            std::fprintf(lgnf, " ");
        }
        std::fprintf(lgnf, "%lu", s.id);
        first = false;
    }
    std::fprintf(lgnf, "\nSEATS=");
    first = true;
    for (auto &s: lgn.sessions) {
        if (!first) {
            std::fprintf(lgnf, " ");
        }
        if (s.s_seat.empty()) {
            continue;
        }
        std::fprintf(lgnf, "%s", s.s_seat.data());
        first = false;
    }
    std::fprintf(lgnf, "\n");
    /* done writing */
    std::fclose(lgnf);
    /* now rename to real file */
    if (renameat(dirfd_users, tmpname, dirfd_users, uname) < 0) {
        print_err("msg: user renameat failed (%s)", strerror(errno));
        unlinkat(dirfd_users, tmpname, 0);
        return false;
    }
    return true;
}

static bool write_sdata(session const &sess) {
    char sessname[32], tmpname[32];
    std::snprintf(tmpname, sizeof(tmpname), "%lu.tmp", sess.id);
    std::snprintf(sessname, sizeof(sessname), "%lu", sess.id);
    auto &lgn = *sess.lgn;
    int omask = umask(0);
    int sessfd = openat(
        dirfd_sessions, tmpname, O_CREAT | O_TRUNC | O_WRONLY, 0644
    );
    if (sessfd < 0) {
        print_err("msg: session tmpfile failed (%s)", strerror(errno));
        umask(omask);
        return false;
    }
    umask(omask);
    auto *sessf = fdopen(sessfd, "w");
    if (!sessf) {
        print_err("msg: session fdopen failed (%s)", strerror(errno));
        close(sessfd);
        return false;
    }
    /* now write all the session data */
    std::fprintf(
        sessf,
        "UID=%u\n"
        "USER=%s\n",
        lgn.uid,
        lgn.username.data()
    );
    if (sess.vtnr) {
        std::fprintf(sessf, "IS_DISPLAY=1\n");
    }
    std::fprintf(sessf, "REMOTE=%d\n", int(sess.remote));
    std::fprintf(sessf, "TYPE=%s\n", sess.s_type.data());
    std::fprintf(sessf, "ORIGINAL_TYPE=%s\n", sess.s_type.data());
    std::fprintf(sessf, "CLASS=%s\n", sess.s_class.data());
    if (!sess.s_seat.empty()) {
        std::fprintf(sessf, "SEAT=%s\n", sess.s_seat.data());
    }
    if (!sess.s_tty.empty()) {
        std::fprintf(sessf, "TTY=%s\n", sess.s_tty.data());
    }
    if (!sess.s_service.empty()) {
        std::fprintf(sessf, "SERVICE=%s\n", sess.s_service.data());
    }
    if (sess.vtnr) {
        std::fprintf(sessf, "VTNR=%lu\n", sess.vtnr);
    }
    std::fprintf(sessf, "LEADER=%ld\n", long(sess.lpid));
    /* done writing */
    std::fclose(sessf);
    /* now rename to real file */
    if (renameat(dirfd_sessions, tmpname, dirfd_sessions, sessname) < 0) {
        print_err("msg: session renameat failed (%s)", strerror(errno));
        unlinkat(dirfd_sessions, tmpname, 0);
        return false;
    }
    return write_udata(lgn);
}

static void drop_udata(login const &lgn) {
    char lgname[64];
    std::snprintf(lgname, sizeof(lgname), "%u", lgn.uid);
    unlinkat(dirfd_users, lgname, 0);
}

static void drop_sdata(session const &sess) {
    char sessname[64];
    std::snprintf(sessname, sizeof(sessname), "%lu", sess.id);
    unlinkat(dirfd_sessions, sessname, 0);
}

static bool sock_block(int fd, short events) {
    if (errno == EINTR) {
        return true;
    } else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
        return false;
    }
    /* re-poll */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;
    for (;;) {
        auto pret = poll(&pfd, 1, -1);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        } else if (pret == 0) {
            continue;
        }
        break;
    }
    return true;
}

static bool send_full(int fd, void const *buf, size_t len) {
    auto *cbuf = static_cast<unsigned char const *>(buf);
    while (len) {
        auto ret = send(fd, cbuf, len, 0);
        if (ret < 0) {
            if (sock_block(fd, POLLOUT)) {
                continue;
            }
            print_err("msg: send failed (%s)", strerror(errno));
            return false;
        }
        cbuf += ret;
        len -= ret;
    }
    return true;
}

static bool send_msg(int fd, unsigned char msg) {
    if (!send_full(fd, &msg, sizeof(msg))) {
        return false;
    }
    return (msg != MSG_ERR);
}

static bool recv_val(int fd, void *buf, size_t sz) {
    auto ret = recv(fd, buf, sz, 0);
    if (ret < 0) {
        if (errno == EINTR) {
            return recv_val(fd, buf, sz);
        }
        print_err("msg: recv failed (%s)", strerror(errno));
    }
    if (size_t(ret) != sz) {
        print_err("msg: partial recv despite peek");
        return false;
    }
    return true;
}

static bool recv_str(
    session &sess, std::string &outs, unsigned int minlen, unsigned int maxlen
) {
    char buf[1024];
    if (!sess.str_left) {
        print_dbg("msg: str start");
        outs.clear();
        size_t slen;
        if (!recv_val(sess.fd, &slen, sizeof(slen))) {
            return false;
        }
        if ((slen < minlen) || (slen > maxlen)) {
            print_err("msg: invalid string length");
            return false;
        }
        sess.str_left = slen;
        /* we are awaiting string, which may come in arbitrary chunks */
        sess.needed = 0;
        return true;
    }
    auto left = sess.str_left;
    if (left > sizeof(buf)) {
        left = sizeof(buf);
    }
    auto ret = recv(sess.fd, buf, left, 0);
    if (ret < 0) {
        if (errno == EINTR) {
            return recv_str(sess, outs, minlen, maxlen);
        } else if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            return true;
        }
    }
    outs.append(buf, ret);
    sess.str_left -= ret;
    return true;
}

static bool handle_read(int fd) {
    int sess_needed;
    /* try get existing session */
    auto *sess = get_session(fd);
    int *pidx = nullptr;
    /* no session: initialize one, expect initial data */
    if (!sess) {
        sess_needed = sizeof(unsigned char);
        for (auto &pfd: pending_sess) {
            if (pfd == fd) {
                pidx = &pfd;
                sess_needed = sizeof(unsigned int);
                break;
            }
        }
    } else {
        sess_needed = sess->needed;
    }
    /* check if we have enough data, otherwise re-poll */
    if (sess_needed) {
        int avail;
        auto ret = ioctl(fd, FIONREAD, &avail);
        if (ret < 0) {
            print_err("msg: ioctl failed (%s)", strerror(errno));
            return false;
        }
        if (avail < sess_needed) {
            return true;
        }
    }
    /* must be an initial message */
    if (!sess && !pidx) {
        unsigned char msg;
        if (!recv_val(fd, &msg, sizeof(msg))) {
            return false;
        }
        if (msg != MSG_START) {
            /* unexpected message */
            print_err("msg: expected MSG_START, got %u", msg);
            return false;
        }
        pending_sess.push_back(fd);
        return true;
    }
    /* pending a uid */
    if (!sess) {
        unsigned int uid;
        /* drop from pending */
        pending_sess.erase(pending_sess.begin() + (pidx - &pending_sess[0]));
        /* now receive uid */
        if (!recv_val(fd, &uid, sizeof(uid))) {
            return false;
        }
        sess = handle_session_new(fd, uid);
        if (!sess) {
            return send_msg(fd, MSG_ERR);
        }
        /* expect vtnr */
        sess->needed = sizeof(unsigned long);
        return true;
    }
    /* handle the right section of handshake */
    if (sess->handshake) {
        if (sess->pend_vtnr) {
            print_dbg("msg: get session vtnr");
            if (!recv_val(fd, &sess->vtnr, sizeof(sess->vtnr))) {
                return false;
            }
            /* remote */
            sess->needed = sizeof(bool);
            sess->pend_vtnr = 0;
            return true;
        }
        if (sess->pend_remote) {
            print_dbg("msg: get remote");
            if (!recv_val(fd, &sess->remote, sizeof(sess->remote))) {
                return false;
            }
            /* service str */
            sess->needed = sizeof(size_t);
            sess->pend_remote = 0;
            return true;
        }
#define GET_STR(type, min, max, code) \
        if (sess->pend_##type) { \
            print_dbg("msg: get " #type); \
            if (!recv_str(*sess, sess->s_##type, min, max)) { \
                return false; \
            } \
            if (!sess->str_left) { \
                sess->pend_##type = false; \
                /* we are waiting for length of next string */ \
                sess->needed = sizeof(size_t); \
                print_dbg("msg: got \"%s\"", sess->s_##type.data()); \
                code \
            } \
            return true; \
        }
        GET_STR(service, 1, 64,)
        GET_STR(type, 1, 16,)
        GET_STR(class, 1, 16,)
        GET_STR(desktop, 0, 64,)
        GET_STR(seat, 0, 32,)
        GET_STR(tty, 0, 16,)
        GET_STR(display, 0, 16,)
        GET_STR(ruser, 0, 256,)
        GET_STR(rhost, 0, 256, goto handshake_finish;)
#undef GET_STR
        /* should be unreachable */
        print_dbg("msg: unreachable handshake");
        return false;
    }
handshake_finish:
    if (sess->handshake) {
        /* from this point the protocol is byte-sized messages only */
        sess->needed = sizeof(unsigned char);
        sess->handshake = 0;
        /* finish startup */
        if (!sess->lgn->srv_wait) {
            /* already started, reply with ok */
            print_dbg("msg: done");
            /* establish internal session file */
            if (!write_sdata(*sess)) {
                return false;
            }
            if (!send_msg(fd, MSG_OK_DONE)) {
                return false;
            }
        } else {
            if (sess->lgn->srv_pid == -1) {
                if (sess->lgn->term_pid != -1) {
                    /* still waiting for old service manager to die */
                    print_dbg("msg: still waiting for old srv term");
                    sess->lgn->srv_pending = true;
                } else {
                    print_dbg("msg: start service manager");
                    if (!srv_start(*sess->lgn)) {
                        return false;
                    }
                    /* establish internal session file */
                    if (!write_sdata(*sess)) {
                        return false;
                    }
                }
            }
            print_dbg("msg: wait");
            return send_msg(fd, MSG_OK_WAIT);
        }
        return true;
    }
    /* get msg */
    unsigned char msg;
    if (!recv_val(fd, &msg, sizeof(msg))) {
        return false;
    }
    if (msg != MSG_REQ_ENV) {
        print_err("msg: invalid message %u (%d)", msg, fd);
        return false;
    }
    print_dbg("msg: session environment request");
    /* data message */
    if (!send_msg(fd, MSG_ENV)) {
        return false;
    }
    unsigned int rlen = sess->lgn->rundir.size();
    if (!rlen) {
        /* no rundir means no env, send a zero */
        print_dbg("msg: no rundir, not sending env");
        return send_full(fd, &rlen, sizeof(rlen));
    }
    /* we have a rundir, compute an environment block */
    unsigned int elen = 0;
    bool got_bus = false;
    /* declare some constants we need */
    char const dpfx[] = "DBUS_SESSION_BUS_ADDRESS=unix:path=";
    char const rpfx[] = "XDG_RUNTIME_DIR=";
    char const dsfx[] = "/bus";
    /* we can optionally export session bus address */
    if (cdata->export_dbus) {
        /* check if the session bus socket exists */
        struct stat sbuf;
        /* first get the rundir descriptor */
        int rdirfd = open(sess->lgn->rundir.data(), O_RDONLY | O_NOFOLLOW);
        if (rdirfd >= 0) {
            if (
                !fstatat(rdirfd, "bus", &sbuf, AT_SYMLINK_NOFOLLOW) &&
                S_ISSOCK(sbuf.st_mode)
            ) {
                /* the bus socket exists */
                got_bus = true;
                /* includes null terminator */
                elen += sizeof(dpfx) + sizeof(dsfx) - 1;
                elen += rlen;
            }
            close(rdirfd);
        }
    }
    /* we can also export rundir if we're managing it */
    if (cdata->manage_rdir) {
        /* includes null terminator */
        elen += sizeof("XDG_RUNTIME_DIR=");
        elen += rlen;
    }
    /* send the total length */
    print_dbg("msg: send len: %u", elen);
    if (!send_full(fd, &elen, sizeof(elen))) {
        return false;
    }
    auto &rdir = sess->lgn->rundir;
    /* now send rundir if we have it */
    if (cdata->manage_rdir) {
        if (!send_full(fd, rpfx, sizeof(rpfx) - 1)) {
            return false;
        }
        /* includes null terminator */
        if (!send_full(fd, rdir.data(), rdir.size() + 1)) {
            return false;
        }
    }
    /* now send bus if we have it */
    if (got_bus) {
        if (!send_full(fd, dpfx, sizeof(dpfx) - 1)) {
            return false;
        }
        if (!send_full(fd, rdir.data(), rdir.size())) {
            return false;
        }
        /* includes null terminator */
        if (!send_full(fd, dsfx, sizeof(dsfx))) {
            return false;
        }
    }
    print_dbg("msg: sent env, done");
    /* we've sent all */
    return true;
}

struct sig_data {
    int sign;
    void *datap;
};

static void sig_handler(int sign) {
    sig_data d;
    d.sign = sign;
    d.datap = nullptr;
    write(sigpipe[1], &d, sizeof(d));
}

static void timer_handler(int sign, siginfo_t *si, void *) {
    sig_data d;
    d.sign = sign;
    d.datap = si->si_value.sival_ptr;
    write(sigpipe[1], &d, sizeof(d));
}

static bool check_linger(login const &lgn) {
    if (cdata->linger_never) {
        return false;
    }
    if (cdata->linger) {
        return true;
    }
    int dfd = open(LINGER_PATH, O_RDONLY);
    if (dfd < 0) {
        return false;
    }
    struct stat lbuf;
    bool ret = (!fstatat(
        dfd, lgn.username.data(), &lbuf, AT_SYMLINK_NOFOLLOW
    ) && S_ISREG(lbuf.st_mode));
    close(dfd);
    return ret;
}

/* terminate given conn, but only if within login */
static bool conn_term_login(login &lgn, int conn) {
    for (auto cit = lgn.sessions.begin(); cit != lgn.sessions.end(); ++cit) {
        if (cit->fd != conn) {
            continue;
        }
        print_dbg("conn: close %d for login %u", conn, lgn.uid);
        drop_sdata(*cit);
        lgn.sessions.erase(cit);
        write_udata(lgn);
        /* empty now; shut down login */
        if (lgn.sessions.empty() && !check_linger(lgn)) {
            print_dbg("srv: stop");
            if (lgn.srv_pid != -1) {
                print_dbg("srv: term");
                kill(lgn.srv_pid, SIGTERM);
                lgn.term_pid = lgn.srv_pid;
                /* just in case */
                lgn.arm_timer(kill_timeout);
            } else {
                /* if no service manager, drop the dir early; otherwise
                 * wait because we need to remove the boot service first
                 */
                lgn.remove_sdir();
                drop_udata(lgn);
            }
            lgn.srv_pid = -1;
            lgn.start_pid = -1;
            lgn.srv_wait = true;
        }
        close(conn);
        return true;
    }
    return false;
}

static void conn_term(int conn) {
    for (auto &lgn: logins) {
        if (conn_term_login(lgn, conn)) {
            return;
        }
    }
    /* wasn't a session, may be pending */
    for (auto it = pending_sess.begin(); it != pending_sess.end(); ++it) {
        if (*it == conn) {
            pending_sess.erase(it);
            break;
        }
    }
    /* in any case, close */
    close(conn);
}

static bool sock_new(char const *path, int &sock, mode_t mode) {
    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        print_err("socket failed (%s)", strerror(errno));
        return false;
    }

    /* set buffers */
    int bufsz = 4096;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz)) < 0) {
        print_err("setssockopt failed (%s)", strerror(errno));
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz)) < 0) {
        print_err("setssockopt failed (%s)", strerror(errno));
    }

    print_dbg("socket: created %d for %s", sock, path);

    sockaddr_un un;
    std::memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;

    auto plen = std::strlen(path);
    if (plen >= sizeof(un.sun_path)) {
        print_err("socket: path name %s too long", path);
        close(sock);
        return false;
    }

    std::memcpy(un.sun_path, path, plen + 1);
    /* no need to check this */
    unlink(path);

    if (bind(sock, reinterpret_cast<sockaddr const *>(&un), sizeof(un)) < 0) {
        print_err("bind failed (%s)", strerror(errno));
        close(sock);
        return false;
    }
    print_dbg("socket: bound %d for %s", sock, path);

    if (chmod(path, mode) < 0) {
        print_err("chmod failed (%s)", strerror(errno));
        goto fail;
    }
    print_dbg("socket: permissions set");

    if (listen(sock, SOMAXCONN) < 0) {
        print_err("listen failed (%s)", strerror(errno));
        goto fail;
    }
    print_dbg("socket: listen");

    print_dbg("socket: done");
    return true;

fail:
    unlink(path);
    close(sock);
    return false;
}

static bool drop_login(login &lgn) {
    /* terminate all connections belonging to this login */
    print_dbg("turnstiled: drop login %u", lgn.uid);
    for (std::size_t j = 2; j < fds.size(); ++j) {
        if (conn_term_login(lgn, fds[j].fd)) {
            fds[j].fd = -1;
            fds[j].revents = 0;
        }
    }
    /* mark the login to repopulate from passwd */
    lgn.repopulate = true;
    /* this should never happen unless we have a bug */
    if (!lgn.sessions.empty()) {
        print_err("turnstiled: sessions not empty, it should be");
        /* unrecoverable */
        return false;
    }
    return true;
}

static bool sig_handle_term() {
    print_dbg("turnstiled: term");
    bool succ = true;
    /* close the control socket */
    close(ctl_sock);
    /* drop logins */
    for (auto &lgn: logins) {
        if (!drop_login(lgn)) {
            succ = false;
        }
    }
    /* shrink the descriptor list to just signal pipe */
    fds.resize(1);
    return succ;
}

static bool sig_handle_alrm(void *data) {
    print_dbg("turnstiled: sigalrm");
    auto &lgn = *static_cast<login *>(data);
    /* disarm the timer if armed */
    if (lgn.timer_armed) {
        print_dbg("turnstiled: drop timer");
        lgn.disarm_timer();
    } else {
        print_dbg("turnstiled: spurious alarm, ignoring");
        return true;
    }
    if (lgn.term_pid != -1) {
        if (lgn.kill_tried) {
            print_err(
                "turnstiled: service manager process %ld refused to die",
                static_cast<long>(lgn.term_pid)
            );
            return false;
        }
        /* waiting for service manager to die and it did not die, try again
         * this will propagate as SIGKILL in the double-forked process
         */
        kill(lgn.term_pid, SIGTERM);
        lgn.kill_tried = true;
        /* re-arm the timer, if that fails again, we give up */
        lgn.arm_timer(kill_timeout);
        return true;
    }
    /* terminate all connections belonging to this login */
    return drop_login(lgn);
}

/* this is called upon receiving a SIGCHLD
 *
 * can happen for 3 things:
 *
 * the service manager instance which is still supposed to be running, in
 * which case we attempt to restart it (except if it never signaled readiness,
 * in which case we give up, as we'd likely loop forever)
 *
 * the readiness job, which waits for the bootup to finish, and is run once
 * the service manager has opened its control socket; in those cases we notify
 * all pending connections and disarm the timeout (and mark the login ready)
 *
 * or the service manager instance which has stopped (due to logout typically),
 * in which case we take care of removing the generated service directory and
 * possibly clear the rundir (if managed)
 */
static bool srv_reaper(pid_t pid) {
    print_dbg("srv: reap %u", (unsigned int)pid);
    for (auto &lgn: logins) {
        if (pid == lgn.srv_pid) {
            lgn.srv_pid = -1;
            lgn.start_pid = -1; /* we don't care anymore */
            lgn.disarm_timer();
            if (lgn.srv_wait) {
                /* failed without ever having signaled readiness
                 * let the login proceed but indicate an error
                 */
                print_err("srv: died without notifying readiness");
                /* clear rundir if needed */
                if (lgn.manage_rdir) {
                    rundir_clear(lgn.rundir.data());
                    lgn.manage_rdir = false;
                }
                return drop_login(lgn);
            }
            return srv_start(lgn);
        } else if (pid == lgn.start_pid) {
            /* reaping service startup jobs */
            print_dbg("srv: ready notification");
            for (auto &sess: lgn.sessions) {
                send_msg(sess.fd, MSG_OK_DONE);
            }
            /* disarm an associated timer */
            print_dbg("srv: disarm timer");
            lgn.disarm_timer();
            lgn.start_pid = -1;
            lgn.srv_wait = false;
        } else if (pid == lgn.term_pid) {
            /* if there was a timer on the login, safe to drop it now */
            lgn.disarm_timer();
            lgn.remove_sdir();
            /* clear rundir if needed */
            if (lgn.manage_rdir) {
                rundir_clear(lgn.rundir.data());
                lgn.manage_rdir = false;
            }
            /* mark to repopulate if there are no sessions */
            if (lgn.sessions.empty()) {
                drop_udata(lgn);
                lgn.repopulate = true;
            }
            lgn.term_pid = -1;
            lgn.kill_tried = false;
            if (lgn.srv_pending) {
                return srv_start(lgn);
            }
        }
    }
    return true;
}

static bool sig_handle_chld() {
    pid_t wpid;
    int status;
    print_dbg("turnstiled: sigchld");
    /* reap */
    while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* deal with each pid here */
        if (!srv_reaper(wpid)) {
            print_err(
                "turnstiled: failed to restart service manager (%u)\n",
                static_cast<unsigned int>(wpid)
            );
            /* this is an unrecoverable condition */
            return false;
        }
    }
    return true;
}

static bool fd_handle_pipe(std::size_t i) {
    if (fds[i].revents == 0) {
        return true;
    }
    /* find if this is a pipe */
    login *lgn = nullptr;
    for (auto &lgnr: logins) {
        if (fds[i].fd == lgnr.userpipe) {
            lgn = &lgnr;
            break;
        }
    }
    if (!lgn) {
        /* this should never happen */
        return false;
    }
    bool done = false;
    if (fds[i].revents & POLLIN) {
        /* read the string from the pipe */
        for (;;) {
            char c;
            if (read(fds[i].fd, &c, 1) != 1) {
                break;
            }
            if ((c == '\0') || (lgn->srvstr.size() >= PATH_MAX)) {
                /* done receiving */
                done = true;
                break;
            }
            lgn->srvstr.push_back(c);
        }
    }
    if (done || (fds[i].revents & POLLHUP)) {
        print_dbg("pipe: close");
        /* kill the pipe, we don't need it anymore */
        close(lgn->userpipe);
        lgn->userpipe = -1;
        /* just in case */
        lgn->pipe_queued = false;
        fds[i].fd = -1;
        fds[i].revents = 0;
        --npipes;
        /* unlink the pipe */
        unlinkat(lgn->dirfd, "ready", 0);
        print_dbg("pipe: gone");
        /* wait for the boot service to come up */
        if (!srv_boot(*lgn, cdata->backend.data())) {
            /* this is an unrecoverable condition */
            return false;
        }
        /* reset the buffer for next time */
        lgn->srvstr.clear();
    }
    return true;
}

static bool fd_handle_conn(std::size_t i) {
    if (fds[i].revents == 0) {
        return true;
    }
    if (fds[i].revents & POLLHUP) {
        print_dbg("conn: hup %d", fds[i].fd);
        conn_term(fds[i].fd);
        fds[i].fd = -1;
        fds[i].revents = 0;
        return true;
    }
    if (fds[i].revents & POLLIN) {
        /* input on connection */
        try {
            print_dbg("conn: read %d", fds[i].fd);
            if (!handle_read(fds[i].fd)) {
                goto read_fail;
            }
        } catch (std::bad_alloc const &) {
            goto read_fail;
        }
    }
    return true;
read_fail:
    print_err("read: handler failed (terminate connection)");
    conn_term(fds[i].fd);
    fds[i].fd = -1;
    fds[i].revents = 0;
    return true;
}

static void sock_handle_conn() {
    if (!fds[1].revents) {
        return;
    }
    for (;;) {
        auto afd = accept4(
            fds[1].fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC
        );
        if (afd < 0) {
            if (errno != EAGAIN) {
                /* should not happen? disregard the connection */
                print_err("accept4 failed (%s)", strerror(errno));
            }
            break;
        }
        auto &rfd = fds.emplace_back();
        rfd.fd = afd;
        rfd.events = POLLIN | POLLHUP;
        rfd.revents = 0;
        print_dbg("conn: accepted %d for %d", afd, fds[1].fd);
    }
}

int main(int argc, char **argv) {
    /* establish simple signal handler for sigchld */
    {
        struct sigaction sa{};
        sa.sa_handler = sig_handler;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGINT, &sa, nullptr);
    }
    /* establish more complicated signal handler for timers */
    {
        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sa.sa_sigaction = timer_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, nullptr);
    }

    /* prealloc a bunch of space */
    logins.reserve(16);
    fds.reserve(64);
    pending_sess.reserve(16);

    openlog("turnstiled", LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    syslog(LOG_INFO, "Initializing turnstiled...");

    /* initialize configuration structure */
    cfg_data cdata_val;
    cdata = &cdata_val;

    if (argc >= 2) {
        cfg_read(argv[1]);
    } else {
        cfg_read(DEFAULT_CFG_PATH);
    }

    if (!cdata->manage_rdir && !std::getenv(
        "TURNSTILED_LINGER_ENABLE_FORCE"
    )) {
        /* we don't want to linger when we are not in charge of the rundir,
         * because services may be relying on it; we can never really delete
         * the rundir when lingering, and something like elogind might
         *
         * for those who are aware of the consequences and have things handled
         * on their own, they can start the daemon with the env variable
         */
        cdata->linger_never = true;
    }

    print_dbg("turnstiled: init signal fd");

    {
        struct stat pstat;
        int dfd = open(RUN_PATH, O_RDONLY | O_NOFOLLOW);
        /* ensure the base path exists and is a directory */
        if (fstat(dfd, &pstat) || !S_ISDIR(pstat.st_mode)) {
            print_err("turnstiled base path does not exist");
            return 1;
        }
        dirfd_base = dir_make_at(dfd, SOCK_DIR, 0755);
        if (dirfd_base < 0) {
            print_err("failed to create base directory (%s)", strerror(errno));
            return 1;
        }
        dirfd_users = dir_make_at(dirfd_base, "users", 0755);
        if (dirfd_users < 0) {
            print_err("failed to create users directory (%s)", strerror(errno));
            return 1;
        }
        dirfd_sessions = dir_make_at(dirfd_base, "sessions", 0755);
        if (dirfd_sessions < 0) {
            print_err(
                "failed to create sessions directory (%s)", strerror(errno)
            );
            return 1;
        }
        close(dfd);
    }
    /* ensure it is not accessible by service manager child processes */
    if (
        fcntl(dirfd_base, F_SETFD, FD_CLOEXEC) ||
        fcntl(dirfd_users, F_SETFD, FD_CLOEXEC) ||
        fcntl(dirfd_sessions, F_SETFD, FD_CLOEXEC)
    ) {
        print_err("fcntl failed (%s)", strerror(errno));
        return 1;
    }

    /* use a strict mask */
    umask(077);

    /* signal pipe */
    {
        if (pipe(sigpipe) < 0) {
            print_err("pipe failed (%s)", strerror(errno));
            return 1;
        }
        if (
            (fcntl(sigpipe[0], F_SETFD, FD_CLOEXEC) < 0) ||
            (fcntl(sigpipe[1], F_SETFD, FD_CLOEXEC) < 0)
        ) {
            print_err("fcntl failed (%s)", strerror(errno));
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = sigpipe[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    print_dbg("turnstiled: init control socket");

    /* main control socket */
    {
        if (!sock_new(DAEMON_SOCK, ctl_sock, CSOCK_MODE)) {
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = ctl_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    print_dbg("turnstiled: main loop");

    std::size_t i = 0, curpipes;
    bool term = false;

    /* main loop */
    for (;;) {
        print_dbg("turnstiled: poll");
        auto pret = poll(fds.data(), fds.size(), -1);
        if (pret < 0) {
            /* interrupted by signal */
            if (errno == EINTR) {
                goto do_compact;
            }
            print_err("poll failed (%s)", strerror(errno));
            return 1;
        } else if (pret == 0) {
            goto do_compact;
        }
        /* check signal fd */
        print_dbg("turnstiled: check signal");
        if (fds[0].revents == POLLIN) {
            sig_data sd;
            if (read(fds[0].fd, &sd, sizeof(sd)) != sizeof(sd)) {
                print_err("signal read failed (%s)", strerror(errno));
                goto do_compact;
            }
            if (sd.sign == SIGALRM) {
                if (!sig_handle_alrm(sd.datap)) {
                    return 1;
                }
                goto signal_done;
            }
            if ((sd.sign == SIGTERM) || (sd.sign == SIGINT)) {
                if (!sig_handle_term()) {
                    return 1;
                }
                term = true;
                goto signal_done;
            }
            /* this is a SIGCHLD */
            if (!sig_handle_chld()) {
                return 1;
            }
        }
signal_done:
        print_dbg("turnstiled: check term");
        if (term) {
            /* check if there are any more live processes */
            bool die_now = true;
            for (auto &lgn: logins) {
                if ((lgn.srv_pid >= 0) || (lgn.term_pid >= 0)) {
                    /* still waiting for something to die */
                    die_now = false;
                    break;
                }
            }
            if (die_now) {
                /* no more managed processes */
                return 0;
            }
            /* the only thing to handle when terminating is signal pipe */
            continue;
        }
        /* check incoming connections on control socket */
        print_dbg("turnstiled: check incoming");
        sock_handle_conn();
        /* check on pipes; npipes may be changed by fd_handle_pipe */
        curpipes = npipes;
        print_dbg("turnstiled: check pipes");
        for (i = 2; i < (curpipes + 2); ++i) {
            try {
                if (!fd_handle_pipe(i)) {
                    return 1;
                }
            } catch (std::bad_alloc const &) {
                return 1;
            }
        }
        print_dbg("turnstiled: check conns");
        /* check on connections */
        for (; i < fds.size(); ++i) {
            if (!fd_handle_conn(i)) {
                return 1;
            }
        }
do_compact:
        print_dbg("turnstiled: compact");
        /* compact the descriptor list */
        for (auto it = fds.begin(); it != fds.end();) {
            if (it->fd == -1) {
                it = fds.erase(it);
            } else {
                ++it;
            }
        }
        /* queue pipes after control socket */
        for (auto &lgn: logins) {
            if (!lgn.pipe_queued) {
                continue;
            }
            pollfd pfd;
            pfd.fd = lgn.userpipe;
            pfd.events = POLLIN | POLLHUP;
            pfd.revents = 0;
            /* insert in the pipe area so they are polled before conns */
            fds.insert(fds.begin() + 2, pfd);
            /* ensure it's not re-queued again */
            lgn.pipe_queued = false;
            ++npipes;
        }
    }
    for (auto &fd: fds) {
        if (fd.fd >= 0) {
            close(fd.fd);
        }
    }
    return 0;
}

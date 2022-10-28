/* dinit-userservd: handle incoming session requests and start
 *                  (or stop) dinit user instances as necessary
 *
 * the daemon should never exit under "normal" circumstances
 *
 * Copyright 2021 Daniel "q66" Kolesa <q66@chimera-linux.org>
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

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "dinit-userservd.hh"

#ifndef CONF_PATH
#error "No CONF_PATH is defined"
#endif

#define DEFAULT_CFG_PATH CONF_PATH "/dinit-userservd.conf"

/* when stopping dinit, we first do a SIGTERM and set up this timeout,
 * if it fails to quit within that period, we issue a SIGKILL and try
 * this timeout again, after that it is considered unrecoverable
 */
static constexpr std::time_t kill_timeout = 60;

/* global */
cfg_data *cdata = nullptr;

/* the file descriptor for the base directory */
static int userv_dirfd = -1;

struct pending_conn {
    pending_conn():
        pending_uid{1}, pending_gid{1}, pending_hdir{1}
    {}
    int conn = -1;
    char *homedir = nullptr;
    unsigned int uid = 0;
    unsigned int gid = 0;
    unsigned int dirleft = 0;
    unsigned int dirgot  = 0;
    unsigned int pending_uid: 1;
    unsigned int pending_gid: 1;
    unsigned int pending_hdir: 1;

    ~pending_conn() {
        std::free(homedir);
    }
};

session::session() {
    sockptr = csock;
    timer_sev.sigev_notify = SIGEV_SIGNAL;
    timer_sev.sigev_signo = SIGALRM;
    timer_sev.sigev_value.sival_ptr = this;
}

session::~session() {
    std::free(homedir);
}

void session::remove_sdir() {
    unlinkat(userv_dirfd, this->uids, AT_REMOVEDIR);
    close(this->dirfd);
    this->dirfd = -1;
}

bool session::arm_timer(std::time_t timeout) {
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

void session::disarm_timer() {
    if (!timer_armed) {
        return;
    }
    timer_delete(timer);
    timer_armed = false;
}

static std::vector<session> sessions;
static std::vector<pending_conn> pending_conns;

/* file descriptors for poll */
static std::vector<pollfd> fds;
/* number of pipes we are polling on */
static std::size_t npipes = 0;
/* control IPC socket */
static int ctl_sock;

/* dummy "dinit" child process if disabled */
static void dinit_dummy(int pipew) {
    /* we're always ready, the dummy process just sleeps forever */
    if (write(pipew, "poke", 5) != 5) {
        perror("dummy: failed to poke the pipe");
        return;
    }
    close(pipew);
    /* block all signals except the ones we need to terminate */
    sigset_t mask;
    sigfillset(&mask);
    /* kill/stop are ignored, but term is not */
    sigdelset(&mask, SIGTERM);
    sigprocmask(SIG_SETMASK, &mask, nullptr);
    /* this will sleep until a termination signal wakes it */
    pause();
    /* in which case just exit */
    exit(0);
}

/* start the dinit instance for a session */
static bool dinit_start(session &sess) {
    int dpipe[2];
    /* mark as waiting */
    sess.dinit_wait = true;
    /* make rundir if needed, we don't want to create that and session dir
     * any earlier than here as here we are sure the previous instance has
     * definitely terminated and stuff like session dirfd is actually clear
     */
    if (cdata->manage_rdir) {
        print_dbg("dinit: setup rundir for %u", sess.uid);
        if (!rundir_make(sess.rundir, sess.uid, sess.gid)) {
            return false;
        }
    }
    /* set up session dir */
    if (!cdata->disable) {
        print_dbg("dinit: create session dir for %u", sess.uid);
        /* make the directory itself */
        sess.dirfd = dir_make_at(userv_dirfd, sess.uids, 0700);
        if (sess.dirfd < 0) {
            print_err(
                "dinit: failed to make session dir for %u (%s)",
                sess.uid, strerror(errno)
            );
            return false;
        }
        /* ensure it's owned by the user */
        if (fchownat(
            userv_dirfd, sess.uids, sess.uid, sess.gid, AT_SYMLINK_NOFOLLOW
        ) || fcntl(sess.dirfd, F_SETFD, FD_CLOEXEC)) {
            print_err(
                "dinit: session dir setup failed for %u (%s)",
                sess.uid, strerror(errno)
            );
            if (dir_clear_contents(sess.dirfd)) {
                sess.remove_sdir();
            }
            return false;
        }
    }
    /* here we'll receive the dinit socket path once ready to take commands */
    if (pipe2(dpipe, O_NONBLOCK) < 0) {
        print_err("dinit: pipe failed (%s)", strerror(errno));
        return false;
    }
    /* set up the timer, issue SIGLARM when it fires */
    print_dbg("dinit: timer set");
    if (cdata->dinit_timeout > 0) {
        if (!sess.arm_timer(cdata->dinit_timeout)) {
            return false;
        }
    } else {
        print_dbg("dinit: no timeout");
    }
    /* launch dinit */
    print_dbg("dinit: launch");
    auto pid = fork();
    if (pid == 0) {
        if (cdata->disable) {
            dinit_dummy(dpipe[1]);
            exit(1);
        }
        char pipestr[32];
        std::snprintf(pipestr, sizeof(pipestr), "%d", dpipe[1]);
        dinit_child(sess, pipestr);
        exit(1);
    } else if (pid < 0) {
        print_err("dinit: fork failed (%s)", strerror(errno));
        return false;
    }
    /* close the write end on our side */
    close(dpipe[1]);
    sess.dinit_pending = false;
    sess.dinit_pid = pid;
    sess.userpipe = dpipe[0];
    sess.pipe_queued = true;
    return true;
}

static session *get_session(int fd) {
    for (auto &sess: sessions) {
        for (auto c: sess.conns) {
            if (fd == c) {
                return &sess;
            }
        }
    }
    return nullptr;
}

static bool msg_send(int fd, unsigned int msg) {
    if (send(fd, &msg, sizeof(msg), 0) < 0) {
        print_err("msg: send failed (%s)", strerror(errno));
        return false;
    }
    return (msg != MSG_ERR);
}

static bool handle_session_new(
    int fd, unsigned int msg, pending_conn &it, bool &done
) {
    /* first message after welcome */
    if (it.pending_uid) {
        print_dbg("msg: welcome uid %u", msg);
        it.uid = msg;
        it.pending_uid = 0;
        return true;
    }
    /* first message after uid */
    if (it.pending_gid) {
        print_dbg("msg: welcome gid %u (uid %u)", msg, it.uid);
        it.gid = msg;
        it.pending_gid = 0;
        return true;
    }
    if (it.pending_hdir) {
        print_dbg("msg: getting homedir for %u (length: %u)", it.uid, msg);
        /* no length or too long; reject */
        if (!msg || (msg > DIRLEN_MAX)) {
            return false;
        }
        it.homedir = static_cast<char *>(std::malloc(msg + 1));
        if (!it.homedir) {
            print_dbg("msg: failed to alloc %u bytes for %u", msg, it.uid);
            return false;
        }
        it.dirgot = 0;
        it.dirleft = msg;
        it.pending_hdir = 0;
        return true;
    }
    if (it.dirleft) {
        auto pkt = MSG_SBYTES(it.dirleft);
        std::memcpy(&it.homedir[it.dirgot], &msg, pkt);
        it.dirgot += pkt;
        it.dirleft -= pkt;
    }
    /* not done receiving homedir yet */
    if (it.dirleft) {
        return true;
    }
    /* done receiving, sanitize */
    it.homedir[it.dirgot] = '\0';
    auto hlen = std::strlen(it.homedir);
    if (!hlen) {
        return false;
    }
    while (it.homedir[hlen - 1] == '/') {
        it.homedir[--hlen] = '\0';
    }
    if (!hlen) {
        return false;
    }
    /* must be absolute */
    if (it.homedir[0] != '/') {
        return false;
    }
    /* ensure the homedir exists and is a directory,
     * this also ensures the path is safe to use in
     * unsanitized contexts without escaping
     */
    if (struct stat s; stat(it.homedir, &s) || !S_ISDIR(s.st_mode)) {
        return false;
    }
    /* acknowledge the session */
    print_dbg("msg: welcome %u (%s)", it.uid, it.homedir);
    session *sess = nullptr;
    for (auto &sessr: sessions) {
        if (sessr.uid == it.uid) {
            sess = &sessr;
            break;
        }
    }
    if (!sess) {
        sess = &sessions.emplace_back();
    }
    /* write uid and gid strings */
    std::snprintf(sess->uids, sizeof(sess->uids), "%u", it.uid);
    std::snprintf(sess->gids, sizeof(sess->gids), "%u", it.gid);
    for (auto c: sess->conns) {
        if (c == fd) {
            print_dbg("msg: already have session %u", it.uid);
            return false;
        }
    }
    std::memset(sess->rundir, 0, sizeof(sess->rundir));
    if (!cfg_expand_rundir(
        sess->rundir, sizeof(sess->rundir), cdata->rdir_path.data(),
        sess->uids, sess->gids
    )) {
        print_dbg("msg: failed to expand rundir for %u", it.uid);
        return false;
    }
    print_dbg("msg: setup session %u", it.uid);
    sess->conns.push_back(fd);
    sess->uid = it.uid;
    sess->gid = it.gid;
    std::free(sess->homedir);
    sess->homedir = it.homedir;
    sess->manage_rdir = cdata->manage_rdir;
    it.homedir = nullptr;
    done = true;
    /* reply */
    return true;
}

static bool handle_read(int fd) {
    unsigned int msg;
    auto ret = recv(fd, &msg, sizeof(msg), 0);
    if (ret != sizeof(msg)) {
        if (errno == EAGAIN) {
            return true;
        }
        print_err("msg: recv failed (%s)", strerror(errno));
        return false;
    }
    print_dbg(
        "msg: read %u (%u, %d)", msg & MSG_TYPE_MASK,
        msg >> MSG_TYPE_BITS, fd
    );
    switch (msg & MSG_TYPE_MASK) {
        case MSG_START: {
            /* new login, register it */
            auto &pc = pending_conns.emplace_back();
            pc.conn = fd;
            return msg_send(fd, MSG_OK);
        }
        case MSG_OK: {
            auto *sess = get_session(fd);
            if (!sess) {
                print_dbg("msg: no session for %u", msg);
                return msg_send(fd, MSG_ERR);
            }
            if (!sess->dinit_wait) {
                /* already started, reply with ok */
                print_dbg("msg: done");
                return msg_send(fd, MSG_OK_DONE);
            } else {
                if (sess->dinit_pid == -1) {
                    if (sess->term_pid != -1) {
                        /* we are still waiting for old dinit to terminate */
                        print_dbg("msg: still waiting for old dinit term");
                        sess->dinit_pending = true;
                    } else {
                        print_dbg("msg: start service manager");
                        if (!dinit_start(*sess)) {
                            return false;
                        }
                    }
                }
                msg = MSG_OK_WAIT;
                print_dbg("msg: wait");
                return msg_send(fd, MSG_OK_WAIT);
            }
            break;
        }
        case MSG_REQ_RLEN: {
            auto *sess = get_session(fd);
            /* send rundir length */
            if (!sess->rundir[0]) {
                /* send zero length */
                return msg_send(fd, MSG_DATA);
            }
            auto rlen = std::strlen(sess->rundir);
            if (cdata->manage_rdir) {
                return msg_send(fd, MSG_ENCODE(rlen + DIRLEN_MAX));
            } else {
                return msg_send(fd, MSG_ENCODE(rlen));
            }
        }
        case MSG_REQ_RDATA: {
            auto *sess = get_session(fd);
            msg >>= MSG_TYPE_BITS;
            if (msg == 0) {
                return msg_send(fd, MSG_ERR);
            }
            unsigned int v = 0;
            auto rlen = std::strlen(sess->rundir);
            if (msg > rlen) {
                return msg_send(fd, MSG_ERR);
            }
            auto *rstr = sess->rundir;
            std::memcpy(&v, rstr + rlen - msg, MSG_SBYTES(msg));
            return msg_send(fd, MSG_ENCODE(v));
        }
        case MSG_DATA: {
            msg >>= MSG_TYPE_BITS;
            /* can be uid, gid, homedir size, homedir data,
             * rundir size or rundir data
             */
            for (
                auto it = pending_conns.begin();
                it != pending_conns.end(); ++it
            ) {
                if (it->conn == fd) {
                    bool done = false;
                    if (!handle_session_new(fd, msg, *it, done)) {
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    if (done) {
                        pending_conns.erase(it);
                    }
                    return msg_send(fd, MSG_OK);
                }
            }
            break;
        }
        default:
            break;
    }
    /* unexpected message, terminate the connection */
    return false;
}

static int sigpipe[2] = {-1, -1};

struct sig_data {
    int sign;
    void *datap;
};

static void chld_handler(int sign) {
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

/* terminate given conn, but only if within session */
static bool conn_term_sess(session &sess, int conn) {
    for (auto cit = sess.conns.begin(); cit != sess.conns.end(); ++cit) {
        if (*cit != conn) {
            continue;
        }
        print_dbg(
            "conn: close %d for session %u",
            conn, sess.uid
        );
        sess.conns.erase(cit);
        /* empty now; shut down session */
        if (sess.conns.empty()) {
            print_dbg("dinit: stop");
            if (sess.dinit_pid != -1) {
                print_dbg("dinit: term");
                kill(sess.dinit_pid, SIGTERM);
                sess.term_pid = sess.dinit_pid;
                /* just in case */
                sess.arm_timer(kill_timeout);
            } else {
                /* if no dinit, drop the dir early; otherwise wait
                 * because we need to remove the boot service first
                 */
                sess.remove_sdir();
            }
            sess.dinit_pid = -1;
            sess.start_pid = -1;
            sess.dinit_wait = true;
        }
        close(conn);
        return true;
    }
    return false;
}

static void conn_term(int conn) {
    for (auto &sess: sessions) {
        if (conn_term_sess(sess, conn)) {
            return;
        }
    }
    close(conn);
}

static bool sock_new(char const *path, int &sock) {
    sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        print_err("socket failed (%s)", strerror(errno));
        return false;
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

    if (chmod(path, 0600) < 0) {
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

static bool sig_handle_alrm(void *data) {
    print_dbg("userservd: sigalrm");
    auto &sess = *static_cast<session *>(data);
    /* disarm the timer first, before it has a chance to fire */
    print_dbg("userservd: drop timer");
    if (!sess.timer_armed) {
        /* this should never happen, unrecoverable */
        print_err("timer: handling alrm but timer not armed");
        return false;
    }
    sess.disarm_timer();
    if (sess.term_pid != -1) {
        if (sess.kill_tried) {
            print_err(
                "userservd: dinit process %ld refused to die",
                static_cast<long>(sess.term_pid)
            );
            return false;
        }
        /* we are waiting for dinit to die and it did not die, attempt kill */
        kill(sess.term_pid, SIGKILL);
        sess.kill_tried = true;
        /* re-arm the timer, if that fails again, we give up */
        sess.arm_timer(kill_timeout);
        return true;
    }
    /* terminate all connections belonging to this session */
    print_dbg("userservd: drop session %u", sess.uid);
    for (std::size_t j = 2; j < fds.size(); ++j) {
        if (conn_term_sess(sess, fds[j].fd)) {
            fds[j].fd = -1;
            fds[j].revents = 0;
        }
    }
    /* this should never happen unless we have a bug */
    if (!sess.conns.empty()) {
        print_err("userservd: conns not empty, it should be");
        /* unrecoverable */
        return false;
    }
    return true;
}

/* this is called upon receiving a SIGCHLD
 *
 * can happen for 3 things:
 *
 * the dinit instance which is still supposed to be running, in which case
 * we attempt to restart it (except if it never signaled readiness, in which
 * case we give up, as we'd likely loop forever)
 *
 * the dinitctl start job, which waits for the bootup to finish, and is run
 * once dinit has opened its control socket; in those cases we notify all
 * pending connections and disarm the timeout (and mark the session ready)
 *
 * or the dinit instance which has stopped (due to logout typically), in
 * which case we take care of removing the generated service directory and
 * possibly clear the rundir (if managed)
 */
static bool dinit_reaper(pid_t pid) {
    print_dbg("dinit: check for restarts");
    for (auto &sess: sessions) {
        if (pid == sess.dinit_pid) {
            sess.dinit_pid = -1;
            sess.start_pid = -1; /* we don't care anymore */
            if (sess.dinit_wait) {
                /* failed without ever having signaled readiness
                 * this indicates that we'd probably just loop forever,
                 * so bail out
                 */
                 print_err("dinit: died without notifying readiness");
                 return false;
            }
            return dinit_start(sess);
        } else if (pid == sess.start_pid) {
            /* reaping service startup jobs */
            print_dbg("dinit: ready notification");
            unsigned int msg = MSG_OK_DONE;
            for (auto c: sess.conns) {
                if (send(c, &msg, sizeof(msg), 0) < 0) {
                    print_err("conn: send failed (%s)", strerror(errno));
                }
            }
            /* disarm an associated timer */
            print_dbg("dinit: disarm timer");
            sess.disarm_timer();
            sess.start_pid = -1;
            sess.dinit_wait = false;
        } else if (pid == sess.term_pid) {
            /* if there was a timer on the session, safe to drop it now */
            sess.disarm_timer();
            if (dir_clear_contents(sess.dirfd)) {
                sess.remove_sdir();
            }
            /* clear rundir if needed */
            if (sess.manage_rdir) {
                rundir_clear(sess.rundir);
                sess.manage_rdir = false;
            }
            sess.term_pid = -1;
            sess.kill_tried = false;
            if (sess.dinit_pending) {
                return dinit_start(sess);
            }
        }
    }
    return true;
}

static bool sig_handle_chld() {
    pid_t wpid;
    int status;
    print_dbg("userservd: sigchld");
    /* reap */
    while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* deal with each pid here */
        if (!dinit_reaper(wpid)) {
            print_err(
                "userservd: failed to restart dinit (%u)\n",
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
    session *sess = nullptr;
    for (auto &sessr: sessions) {
        if (fds[i].fd == sessr.userpipe) {
            sess = &sessr;
            break;
        }
    }
    if (!sess) {
        /* this should never happen */
        return false;
    }
    if (fds[i].revents & POLLIN) {
        auto *endp = &sess->csock[sizeof(sess->csock) - 1];
        /* read the socket path */
        for (;;) {
            if (sess->sockptr == endp) {
                /* just in case, break off reading past the limit */
                char b;
                /* eat whatever else is in the pipe */
                while (read(fds[i].fd, &b, 1) == 1) {}
                break;
            }
            if (read(fds[i].fd, sess->sockptr++, 1) != 1) {
                break;
            }
        }
    }
    if (fds[i].revents & POLLHUP) {
        /* kill the pipe, we don't need it anymore */
        close(sess->userpipe);
        sess->userpipe = -1;
        /* just in case */
        sess->pipe_queued = false;
        fds[i].fd = -1;
        fds[i].revents = 0;
        --npipes;
        /* but error early if needed */
        if (!sess->csock[0]) {
            print_err("read failed (%s)", strerror(errno));
            return true;
        }
        /* wait for the boot service to come up */
        if (!dinit_boot(*sess, cdata->disable)) {
            /* this is an unrecoverable condition */
            return false;
        }
        /* reset the buffer for next time */
        sess->sockptr = sess->csock;
        std::memset(sess->csock, 0, sizeof(sess->csock));
    }
    return true;
}

static bool fd_handle_conn(std::size_t i) {
    if (fds[i].revents == 0) {
        return true;
    }
    if (fds[i].revents & POLLHUP) {
        conn_term(fds[i].fd);
        fds[i].fd = -1;
        fds[i].revents = 0;
        return true;
    }
    if (fds[i].revents & POLLIN) {
        /* input on connection */
        if (!handle_read(fds[i].fd)) {
            print_err("read: handler failed (terminate connection)");
            conn_term(fds[i].fd);
            fds[i].fd = -1;
            fds[i].revents = 0;
            return true;
        }
    }
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
    if (signal(SIGCHLD, chld_handler) == SIG_ERR) {
        perror("signal failed");
        return 1;
    }
    /* establish more complicated signal handler for timers */
    {
        struct sigaction sa;
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = timer_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGALRM, &sa, nullptr) == -1) {
            perror("sigaction failed");
            return 1;
        }
    }

    /* prealloc a bunch of space */
    pending_conns.reserve(8);
    sessions.reserve(16);
    fds.reserve(64);

    openlog("dinit-userservd", LOG_CONS | LOG_NDELAY, LOG_DAEMON);

    syslog(LOG_INFO, "Initializing dinit-userservd...");

    /* initialize configuration structure */
    cfg_data cdata_val;
    cdata = &cdata_val;

    if (argc >= 2) {
        cfg_read(argv[1]);
    } else {
        cfg_read(DEFAULT_CFG_PATH);
    }

    print_dbg("userservd: init signal fd");

    {
        struct stat pstat;
        int dfd = open(RUN_PATH, O_RDONLY);
        /* ensure the base path exists and is a directory */
        if (fstat(dfd, &pstat) || !S_ISDIR(pstat.st_mode)) {
            print_err("userservd base path does not exist");
            return 1;
        }
        userv_dirfd = dir_make_at(dfd, SOCK_DIR, 0755);
        if (userv_dirfd < 0) {
            print_err("failed to create base directory (%s)", strerror(errno));
        }
        close(dfd);
    }
    /* ensure it is not accessible by dinit child processes */
    if (fcntl(userv_dirfd, F_SETFD, FD_CLOEXEC)) {
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
        auto &pfd = fds.emplace_back();
        pfd.fd = sigpipe[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    print_dbg("userservd: init control socket");

    /* main control socket */
    {
        if (!sock_new(DAEMON_SOCK, ctl_sock)) {
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = ctl_sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
    }

    print_dbg("userservd: main loop");

    std::size_t i = 0, curpipes;

    /* main loop */
    for (;;) {
        print_dbg("userservd: poll");
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
            /* this is a SIGCHLD */
            if (!sig_handle_chld()) {
                return 1;
            }
        }
signal_done:
        /* check incoming connections on control socket */
        sock_handle_conn();
        /* check on pipes; npipes may be changed by fd_handle_pipe */
        curpipes = npipes;
        for (i = 2; i < (curpipes + 2); ++i) {
            if (!fd_handle_pipe(i)) {
                return 1;
            }
        }
        /* check on connections */
        for (; i < fds.size(); ++i) {
            if (!fd_handle_conn(i)) {
                return 1;
            }
        }
do_compact:
        /* compact the descriptor list */
        for (auto it = fds.begin(); it != fds.end();) {
            if (it->fd == -1) {
                it = fds.erase(it);
            } else {
                ++it;
            }
        }
        /* queue pipes after control socket */
        for (auto &sess: sessions) {
            if (!sess.pipe_queued) {
                continue;
            }
            pollfd pfd;
            pfd.fd = sess.userpipe;
            pfd.events = POLLIN | POLLHUP;
            pfd.revents = 0;
            /* insert in the pipe area so they are polled before conns */
            fds.insert(fds.begin() + 2, pfd);
            /* ensure it's not re-queued again */
            sess.pipe_queued = false;
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
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cerrno>
#include <cassert>
#include <climits>
#include <cctype>
#include <ctime>
#include <limits>
#include <vector>
#include <algorithm>

#include <syslog.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "protocol.hh"

#define DEFAULT_CFG_PATH "/etc/dinit-userservd.conf"

struct cfg_data {
    bool debug = false;
    bool debug_stderr = false;
    bool manage_rdir = false;
    bool export_dbus = true;
    char rdir_path[DIRLEN_MAX];

    cfg_data() {
        std::snprintf(rdir_path, sizeof(rdir_path), "/run/user/%%u");
    }
};

static cfg_data cdata;

/* timeout in case the dinit --user does not signal readiness
 *
 * we keep a timer for each waiting session, if no readiness is received
 * within that timespan, the service manager is terminated and failure
 * is issued to all the connections
 */
static constexpr time_t const dinit_timeout = 60;

/* session information: contains a list of connections (which also provide
 * a way to know when to end the session, as the connection is persistent
 * on the PAM side) and some statekeeping info:
 *
 * - the running service manager instance PID as well as PID of bootup job
 * - the user and group ID of the session's user
 * - dinit readiness notification pipe
 * - whether dinit is currently waiting for readiness notification
 */
struct session {
    std::vector<int> conns{};
    char *homedir = nullptr;
    char dinit_tmp[6];
    pid_t dinit_pid = -1;
    pid_t start_pid = -1;
    pid_t term_pid = -1;
    unsigned int uid = 0;
    unsigned int gid = 0;
    int userpipe[2] = {-1, -1};
    bool dinit_wait = true;
    bool manage_rdir = false;
    char rundir[DIRLEN_MAX];

    ~session() {
        std::free(homedir);
    }
};

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

struct session_timer {
    timer_t timer{};
    sigevent sev{};
    unsigned int uid = 0;
};

static std::vector<session> sessions;
static std::vector<pending_conn> pending_conns;

/* file descriptors for poll */
static std::vector<pollfd> fds;
/* control IPC socket */
static int ctl_sock;
/* requests for new pipes; picked up by the event loop and cleared */
static std::vector<pollfd> pipes;
/* timer list */
static std::vector<session_timer> timers;

#define print_dbg(...) \
    if (cdata.debug) { \
        if (cdata.debug_stderr) { \
            fprintf(stderr, __VA_ARGS__); \
            fputc('\n', stderr); \
        } \
        syslog(LOG_DEBUG, __VA_ARGS__); \
    }

static constexpr int const UID_DIGITS = \
    std::numeric_limits<unsigned int>::digits10;

static bool expand_rundir(
    char *dest, std::size_t destsize, char const *tmpl,
    unsigned int uid, unsigned int gid
) {
    auto destleft = destsize;
    while (*tmpl) {
        auto mark = std::strchr(tmpl, '%');
        if (!mark) {
            /* no formatting mark in the rest of the string, copy all */
            auto rlen = std::strlen(tmpl);
            if (destleft > rlen) {
                /* enough space incl terminating zero */
                std::memcpy(dest, tmpl, rlen + 1);
                return true;
            } else {
                /* not enough space left */
                return false;
            }
        }
        /* copy up to mark */
        auto rlen = std::size_t(mark - tmpl);
        if (rlen) {
            if (destleft > rlen) {
                std::memcpy(dest, tmpl, rlen);
                destleft -= rlen;
                dest += rlen;
            } else {
                /* not enough space left */
                return false;
            }
        }
        /* trailing % or %%, just copy it as is */
        if (!mark[1] || ((mark[1] == '%') && !mark[2])) {
            if (destleft > 1) {
                *dest++ = '%';
                *dest++ = '\0';
                return true;
            }
            return false;
        }
        ++mark;
        unsigned int wnum;
        switch (mark[0]) {
            case 'u':
                wnum = uid;
                goto writenum;
            case 'g':
                wnum = gid;
writenum:
                if (destleft <= 1) {
                    /* not enough space */
                    return false;
                } else {
                    auto nw = std::snprintf(dest, destleft, "%u", wnum);
                    if (nw >= int(destleft)) {
                        return false;
                    }
                    dest += nw;
                    destleft -= nw;
                    tmpl = mark + 1;
                    continue;
                }
            case '%':
                if (destleft > 1) {
                    destleft -= 1;
                    *dest++ = *mark++;
                    tmpl = mark;
                    continue;
                } else {
                    return false;
                }
            default:
                /* copy as is */
                if (destleft > 2) {
                    destleft -= 2;
                    *dest++ = '%';
                    *dest++ = *mark++;
                    tmpl = mark;
                    continue;
                } else {
                    return false;
                }
        }
    }
    *dest = '\0';
    return true;
}

static bool rundir_make(char *rundir, unsigned int uid, unsigned int gid) {
    char *sl = std::strchr(rundir + 1, '/');
    struct stat dstat;
    print_dbg("rundir: make directory %s", rundir);
    /* recursively create all parent paths */
    while (sl) {
        *sl = '\0';
        print_dbg("rundir: try make parent %s", rundir);
        if (stat(rundir, &dstat) || !S_ISDIR(dstat.st_mode)) {
            print_dbg("rundir: make parent %s", rundir);
            if (mkdir(rundir, 0755)) {
                perror("rundir: mkdir failed for path");
                return false;
            }
        }
        *sl = '/';
        sl = strchr(sl + 1, '/');
    }
    /* create rundir with correct permissions */
    if (mkdir(rundir, 0700)) {
        perror("rundir: mkdir failed for rundir");
        return false;
    }
    if (chown(rundir, uid, gid) < 0) {
        perror("rundir: chown failed for rundir");
        rmdir(rundir);
        return false;
    }
    return true;
}

static bool rundir_clear_contents(int dfd) {
    DIR *d = fdopendir(dfd);
    if (!d) {
        perror("rundir: fdopendir failed");
        close(dfd);
        return false;
    }

    unsigned char buf[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    unsigned char *bufp = buf;

    struct dirent *dentb = nullptr, *dent = nullptr;
    std::memcpy(&dentb, &bufp, sizeof(dent));

    for (;;) {
        if (readdir_r(d, dentb, &dent) < 0) {
            perror("rundir: readdir_r failed");
            closedir(d);
            return false;
        }
        if (!dent) {
            break;
        }
        if (
            !std::strcmp(dent->d_name, ".") ||
            !std::strcmp(dent->d_name, "..")
        ) {
            continue;
        }

        print_dbg("rundir: clear %s at %d", dent->d_name, dfd);
        int efd = openat(dfd, dent->d_name, O_RDONLY);
        if (efd < 0) {
            perror("rundir: openat failed");
            closedir(d);
            return false;
        }

        struct stat st;
        if (fstat(efd, &st) < 0) {
            perror("rundir: fstat failed");
            closedir(d);
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!rundir_clear_contents(efd)) {
                closedir(d);
                return false;
            }
        } else {
            close(efd);
        }

        if (unlinkat(
            dfd, dent->d_name, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0
        ) < 0) {
            perror("rundir: unlinkat failed");
            closedir(d);
            return false;
        }
    }

    closedir(d);
    return true;
}

static void rundir_clear(char *rundir) {
    struct stat dstat;
    print_dbg("rundir: clear directory %s", rundir);
    int dfd = open(rundir, O_RDONLY);
    /* non-existent */
    if (fstat(dfd, &dstat)) {
        return;
    }
    /* not a directory */
    if (!S_ISDIR(dstat.st_mode)) {
        print_dbg("rundir: %s is not a directory", rundir);
        return;
    }
    if (rundir_clear_contents(dfd)) {
        /* was empty */
        rmdir(rundir);
    } else {
        print_dbg("rundir: failed to clear contents of %s", rundir);
    }
}

static bool dinit_boot(session &sess, char const *sock) {
    print_dbg("dinit: boot wait");
    auto pid = fork();
    if (pid < 0) {
        perror("dinit: fork failed");
        /* unrecoverable */
        return false;
    }
    if (pid != 0) {
        /* parent process */
        sess.start_pid = pid;
        return true;
    }
    /* child process */
    if (getuid() == 0) {
        if (setgid(sess.gid) != 0) {
            perror("dinit: failed to set gid");
            exit(1);
        }
        if (setuid(sess.uid) != 0) {
            perror("dinit: failed to set uid");
            exit(1);
        }
    }
    execlp(
        "dinitctl", "dinitctl",
        "--socket-path", sock, "start", "boot", nullptr
    );
    exit(1);
    return true;
}

/* global service directory paths */
static constexpr char const *servpaths[] = {
    "/etc/dinit.d/user",
    "/usr/local/lib/dinit.d/user",
    "/usr/lib/dinit.d/user",
};

/* start the dinit instance for a session */
static bool dinit_start(session &sess) {
    /* user dir */
    char rdir[sizeof(USER_PATH) + UID_DIGITS];
    std::snprintf(rdir, sizeof(rdir), USER_PATH, sess.uid);
    /* temporary services dir */
    char tdir[sizeof(USER_DIR) + UID_DIGITS];
    std::snprintf(tdir, sizeof(tdir), USER_DIR, sess.uid);
    /* mark as waiting */
    sess.dinit_wait = true;
    /* create /run/dinit-userservd/$UID if non-existent */
    {
        struct stat pstat;
        if (stat(rdir, &pstat) || !S_ISDIR(pstat.st_mode)) {
            if (mkdir(rdir, 0700)) {
                perror("dinit: mkdir($UID) failed");
                return false;
            }
            if (chown(rdir, sess.uid, sess.gid) < 0) {
                perror("dinit: chown($UID) failed");
                rmdir(rdir);
                return false;
            }
        }
    }
    /* create temporary services dir */
    if (!mkdtemp(tdir)) {
        perror("dinit: mkdtemp failed");
        return false;
    }
    print_dbg("dinit: created service directory (%s)", tdir);
    /* store the characters identifying the tempdir */
    std::memcpy(sess.dinit_tmp, tdir + std::strlen(tdir) - 6, 6);
    if (chown(tdir, sess.uid, sess.gid) < 0) {
        perror("dinit: chown failed");
        rmdir(tdir);
        return false;
    }
    /* user services dir */
    char udir[DIRLEN_MAX + 32];
    std::snprintf(udir, sizeof(udir), "%s/.config/dinit.d", sess.homedir);
    /* set up service file */
    {
        char uboot[sizeof(tdir) + 5];
        std::snprintf(uboot, sizeof(uboot), "%s/boot", tdir);
        auto *f = std::fopen(uboot, "w");
        if (!f) {
            perror("dinit: fopen failed");
            return false;
        }
        /* write boot service */
        std::fprintf(f, "type = internal\n");
        /* wait for a service directory */
        std::fprintf(f, "waits-for.d = %s/boot.d\n", udir);
        std::fclose(f);
        /* set perms otherwise we would infinite loop */
        if (chown(uboot, sess.uid, sess.gid) < 0) {
            perror("dinit: chown failed");
            unlink(uboot);
            return false;
        }
    }
    /* lazily set up user pipe */
    if (sess.userpipe[0] == -1) {
        if (pipe2(sess.userpipe, O_NONBLOCK) < 0) {
            perror("dinit: pipe failed");
            return false;
        }
        auto &pfd = pipes.emplace_back();
        pfd.fd = sess.userpipe[0];
        pfd.events = POLLIN | POLLHUP;
    }
    /* set up the timer, issue SIGLARM when it fires */
    print_dbg("dinit: timer set");
    {
        auto &tm = timers.emplace_back();
        tm.uid = sess.uid;
        tm.sev.sigev_notify = SIGEV_SIGNAL;
        tm.sev.sigev_signo = SIGALRM;
        /* create timer, drop if it fails */
        if (timer_create(CLOCK_MONOTONIC, &tm.sev, &tm.timer) < 0) {
            perror("dinit: timer_create failed");
            timers.pop_back();
            return false;
        }
        /* arm timer, drop if it fails */
        itimerspec tval{};
        tval.it_value.tv_sec = dinit_timeout;
        if (timer_settime(tm.timer, 0, &tval, nullptr) < 0) {
            perror("dinit: timer_settime failed");
            timer_delete(tm.timer);
            timers.pop_back();
            return false;
        }
    }
    /* launch dinit */
    print_dbg("dinit: launch");
    auto pid = fork();
    if (pid == 0) {
        if (getuid() == 0) {
            if (setgid(sess.gid) != 0) {
                perror("dinit: failed to set gid");
                exit(1);
            }
            if (setuid(sess.uid) != 0) {
                perror("dinit: failed to set uid");
                exit(1);
            }
        }
        /* make up an environment */
        char uenv[DIRLEN_MAX + 5];
        char rundir[DIRLEN_MAX + sizeof("XDG_RUNTIME_DIR=")];
        char euid[UID_DIGITS + 5], egid[UID_DIGITS + 5];
        char pnum[32];
        std::snprintf(uenv, sizeof(uenv), "HOME=%s", sess.homedir);
        std::snprintf(euid, sizeof(euid), "UID=%u", sess.uid);
        std::snprintf(egid, sizeof(egid), "GID=%u", sess.gid);
        std::snprintf(pnum, sizeof(pnum), "%d", sess.userpipe[1]);
        if (sess.rundir[0]) {
            std::snprintf(
                rundir, sizeof(rundir), "XDG_RUNTIME_DIR=%s", sess.rundir
            );
        }
        char const *envp[] = {
            uenv, euid, egid,
            "PATH=/usr/local/bin:/usr/bin:/bin",
            sess.rundir[0] ? rundir : nullptr, nullptr
        };
        /* 6 args reserved + whatever service dirs + terminator */
        char const *argp[8 + (sizeof(servpaths) / sizeof(*servpaths)) * 2 + 1];
        std::size_t cidx = 0;
        argp[cidx++] = "dinit";
        argp[cidx++] = "--user";
        argp[cidx++] = "--ready-fd";
        argp[cidx++] = pnum;
        argp[cidx++] = "--services-dir";
        argp[cidx++] = tdir;
        argp[cidx++] = "--services-dir";
        argp[cidx++] = udir;
        for (
            std::size_t i = 0;
            i < (sizeof(servpaths) / sizeof(*servpaths));
            ++i
        ) {
            argp[cidx++] = "--services-dir";
            argp[cidx++] = servpaths[i];
        }
        argp[cidx] = nullptr;
        /* restore umask to user default */
        umask(022);
        /* fire */
        execvpe("dinit", const_cast<char **>(argp), const_cast<char **>(envp));
        exit(1);
    } else if (pid < 0) {
        perror("dinit: fork failed");
        return false;
    }
    sess.dinit_pid = pid;
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
                 std::fprintf(
                     stderr, "dinit: died without notifying readiness\n"
                 );
                 return false;
            }
            return dinit_start(sess);
        } else if (pid == sess.start_pid) {
            /* reaping service startup jobs */
            print_dbg("dinit: ready notification");
            unsigned int msg = MSG_OK_DONE;
            for (auto c: sess.conns) {
                if (send(c, &msg, sizeof(msg), 0) < 0) {
                    perror("conn: send failed");
                }
            }
            /* disarm an associated timer */
            print_dbg("dinit: disarm timer");
            for (
                auto it = timers.begin(); it != timers.end(); ++it
            ) {
                if (it->uid == sess.uid) {
                    timer_delete(it->timer);
                    timers.erase(it);
                    break;
                }
            }
            sess.start_pid = -1;
            sess.dinit_wait = false;
        } else if (pid == sess.term_pid) {
            /* temporary services dir */
            char buf[sizeof(USER_DIR) + UID_DIGITS + 5];
            /* remove the generated service directory best we can
             *
             * it would be pretty harmless to just leave it too
             */
            std::snprintf(buf, sizeof(buf), USER_DIR"/boot", sess.uid);
            std::memcpy(std::strstr(buf, "XXXXXX"), sess.dinit_tmp, 6);
            print_dbg("dinit: remove %s", buf);
            unlink(buf);
            *std::strrchr(buf, '/') = '\0';
            rmdir(buf);
            /* clear rundir if needed */
            if (sess.manage_rdir) {
                rundir_clear(sess.rundir);
                sess.manage_rdir = false;
            }
            sess.term_pid = -1;
        }
    }
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
        perror("msg: send failed");
        return false;
    }
    return (msg != MSG_ERR);
}

static bool handle_read(int fd) {
    unsigned int msg;
    auto ret = recv(fd, &msg, sizeof(msg), 0);
    if (ret != sizeof(msg)) {
        if (errno == EAGAIN) {
            return true;
        }
        perror("msg: recv failed");
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
                    print_dbg("msg: start service manager");
                    if (!dinit_start(*sess)) {
                        return false;
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
            if (cdata.manage_rdir) {
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
                    /* first message after welcome */
                    if (it->pending_uid) {
                        print_dbg("msg: welcome uid %u", msg);
                        it->uid = msg;
                        it->pending_uid = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    /* first message after uid */
                    if (it->pending_gid) {
                        print_dbg(
                            "msg: welcome gid %u (uid %u)", msg, it->uid
                        );
                        it->gid = msg;
                        it->pending_gid = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    if (it->pending_hdir) {
                                print_dbg(
                            "msg: getting homedir for %u (length: %u)",
                            it->uid, msg
                        );
                        /* no length or too long; reject */
                        if (!msg || (msg > DIRLEN_MAX)) {
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                                it->homedir = static_cast<char *>(
                            std::malloc(msg + 1)
                        );
                        if (!it->homedir) {
                            print_dbg(
                                "msg: failed to alloc %u bytes for %u",
                                msg, it->uid
                            );
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                        it->dirgot = 0;
                        it->dirleft = msg;
                        it->pending_hdir = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    if (it->dirleft) {
                        auto pkt = MSG_SBYTES(it->dirleft);
                        std::memcpy(&it->homedir[it->dirgot], &msg, pkt);
                        it->dirgot += pkt;
                        it->dirleft -= pkt;
                    }
                    /* not done receiving homedir yet */
                    if (it->dirleft) {
                        return msg_send(fd, MSG_OK);
                    }
                    /* done receiving, sanitize */
                    it->homedir[it->dirgot] = '\0';
                    auto hlen = std::strlen(it->homedir);
                    if (!hlen) {
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    while (it->homedir[hlen - 1] == '/') {
                        it->homedir[--hlen] = '\0';
                    }
                    if (!hlen) {
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    /* must be absolute */
                    if (it->homedir[0] != '/') {
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    /* ensure the homedir exists and is a directory,
                     * this also ensures the path is safe to use in
                     * unsanitized contexts without escaping
                     */
                    if (
                        struct stat s;
                        stat(it->homedir, &s) || !S_ISDIR(s.st_mode)
                    ) {
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    /* acknowledge the session */
                    print_dbg("msg: welcome %u (%s)", it->uid, it->homedir);
                    session *sess = nullptr;
                    for (auto &sessr: sessions) {
                        if (sessr.uid == it->uid) {
                            sess = &sessr;
                            break;
                        }
                    }
                    if (!sess) {
                        sess = &sessions.emplace_back();
                    }
                    for (auto c: sess->conns) {
                        if (c == fd) {
                            print_dbg(
                                "msg: already have session %u", it->uid
                            );
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                    }
                    std::memset(sess->rundir, 0, sizeof(sess->rundir));
                    if (!expand_rundir(
                        sess->rundir, sizeof(sess->rundir),
                        cdata.rdir_path, it->uid, it->gid
                    )) {
                        print_dbg(
                            "msg: failed to expand rundir for %u", it->uid
                        );
                        pending_conns.erase(it);
                        return msg_send(fd, MSG_ERR);
                    }
                    if (cdata.manage_rdir) {
                        print_dbg("msg: setup rundir for %u", it->uid);
                        if (!rundir_make(sess->rundir, it->uid, it->gid)) {
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                    }
                    print_dbg("msg: setup session %u", it->uid);
                    sess->conns.push_back(fd);
                    sess->uid = it->uid;
                    sess->gid = it->gid;
                    std::free(sess->homedir);
                    sess->homedir = it->homedir;
                    sess->manage_rdir = cdata.manage_rdir;
                    it->homedir = nullptr;
                    pending_conns.erase(it);
                    /* reply */
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

static void sighandler(int sign) {
    write(sigpipe[1], &sign, sizeof(int));
}

static void conn_term(int conn) {
    for (auto &sess: sessions) {
        auto &conv = sess.conns;
        for (
            auto cit = conv.begin(); cit != conv.end(); ++cit
        ) {
            if (*cit != conn) {
                continue;
            }
            print_dbg(
                "conn: close %d for session %u",
                conn, sess.uid
            );
            conv.erase(cit);
            /* empty now; shut down session */
            if (conv.empty()) {
                print_dbg("dinit: stop");
                if (sess.dinit_pid != -1) {
                    print_dbg("dinit: term");
                    kill(sess.dinit_pid, SIGTERM);
                    sess.term_pid = sess.dinit_pid;
                }
                sess.dinit_pid = -1;
                sess.start_pid = -1;
                sess.dinit_wait = true;
            }
            close(conn);
            return;
        }
    }
    close(conn);
}

static bool sock_new(char const *path, int &sock) {
    sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        perror("socket failed");
        return false;
    }

    print_dbg("socket: created %d for %s", sock, path);

    sockaddr_un un;
    std::memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;

    auto plen = std::strlen(path);
    if (plen >= sizeof(un.sun_path)) {
        std::fprintf(stderr, "path name %s too long", path);
        close(sock);
        return false;
    }

    std::memcpy(un.sun_path, path, plen + 1);
    /* no need to check this */
    unlink(path);

    if (bind(sock, reinterpret_cast<sockaddr const *>(&un), sizeof(un)) < 0) {
        perror("bind failed");
        close(sock);
        return false;
    }
    print_dbg("socket: bound %d for %s", sock, path);

    if (chmod(path, 0600) < 0) {
        perror("chmod failed");
        goto fail;
    }
    print_dbg("socket: permissions set");

    if (listen(sock, SOMAXCONN) < 0) {
        perror("listen failed");
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

static void read_bool(char const *name, char const *value, bool &val) {
    if (!std::strcmp(value, "yes")) {
        val = true;
    } else if (!std::strcmp(value, "no")) {
        val = false;
    } else {
        syslog(
            LOG_WARNING,
            "Invalid configuration value '%s' for '%s' (expected yes/no)",
            value, name
        );
    }
}

static void read_cfg(char const *cfgpath) {
    char buf[DIRLEN_MAX];

    auto *f = std::fopen(cfgpath, "r");
    if (!f) {
        syslog(
            LOG_NOTICE, "No configuration file '%s', using defaults", cfgpath
        );
        return;
    }

    while (std::fgets(buf, DIRLEN_MAX, f)) {
        auto slen = strlen(buf);
        /* ditch the rest of the line if needed */
        if ((buf[slen - 1] != '\n')) {
            while (!std::feof(f)) {
                auto c = std::fgetc(f);
                if (c == '\n') {
                    std::fgetc(f);
                    break;
                }
            }
        }
        char *bufp = buf;
        /* drop trailing whitespace */
        while (std::isspace(bufp[slen - 1])) {
            bufp[--slen] = '\0';
        }
        /* drop leading whitespace */
        while (std::isspace(*bufp)) {
            ++bufp;
        }
        /* comment or empty line */
        if (!*bufp || (*bufp == '#')) {
            continue;
        }
        /* find the assignment */
        char *ass = strchr(bufp, '=');
        /* invalid */
        if (!ass || (ass == bufp)) {
            syslog(LOG_WARNING, "Malformed configuration line: %s", bufp);
            continue;
        }
        *ass = '\0';
        /* find the name */
        char *preass = (ass - 1);
        while (std::isspace(*preass)) {
            *preass-- = '\0';
        }
        /* empty name */
        if (preass == bufp) {
            syslog(LOG_WARNING, "Invalud configuration line name: %s", bufp);
            continue;
        }
        /* find the value */
        while (std::isspace(*++ass)) {
            continue;
        }
        /* supported config lines */
        if (!std::strcmp(bufp, "debug")) {
            read_bool("debug", ass, cdata.debug);
        } else if (!std::strcmp(bufp, "debug_stderr")) {
            read_bool("debug_stderr", ass, cdata.debug_stderr);
        } else if (!std::strcmp(bufp, "manage_rundir")) {
            read_bool("manage_rundir", ass, cdata.manage_rdir);
        } else if (!std::strcmp(bufp, "export_dbus_address")) {
            read_bool("export_dbus_address", ass, cdata.export_dbus);
        } else if (!std::strcmp(bufp, "rundir_path")) {
            std::snprintf(cdata.rdir_path, sizeof(cdata.rdir_path), "%s", ass);
        }
    }
}

int main(int argc, char **argv) {
    if (signal(SIGCHLD, sighandler) == SIG_ERR) {
        perror("signal failed");
    }
    if (signal(SIGALRM, sighandler) == SIG_ERR) {
        perror("signal failed");
    }

    /* prealloc a bunch of space */
    pending_conns.reserve(8);
    sessions.reserve(16);
    timers.reserve(16);
    fds.reserve(64);
    pipes.reserve(8);

    openlog("dinit-userservd", LOG_CONS, LOG_DAEMON);

    syslog(LOG_INFO, "Initializing dinit-userservd...");

    if (argc >= 2) {
        read_cfg(argv[1]);
    } else {
        read_cfg(DEFAULT_CFG_PATH);
    }

    print_dbg("userservd: init signal fd");

    {
        struct stat pstat;
        if (stat(SOCK_PATH, &pstat) || !S_ISDIR(pstat.st_mode)) {
            /* create control directory */
            if (mkdir(SOCK_PATH, 0755)) {
                perror("mkdir failed");
                return 1;
            }
        }
    }

    /* use a strict mask */
    umask(077);

    /* signal pipe */
    {
        if (pipe(sigpipe) < 0) {
            perror("pipe failed");
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = sigpipe[0];
        pfd.events = POLLIN;
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
    }

    print_dbg("userservd: main loop");

    std::size_t i = 0;

    /* main loop */
    for (;;) {
        print_dbg("userservd: poll");
        auto pret = poll(fds.data(), fds.size(), -1);
        if (pret < 0) {
            /* interrupted by signal */
            if (errno == EINTR) {
                goto do_compact;
            }
            perror("poll failed");
            return 1;
        } else if (pret == 0) {
            goto do_compact;
        }
        /* check signal fd */
        if (fds[0].revents == POLLIN) {
            int sign;
            if (read(fds[0].fd, &sign, sizeof(int)) != sizeof(int)) {
                perror("signal read failed");
                goto do_compact;
            }
            if (sign == SIGALRM) {
                print_dbg("userservd: sigalrm");
                /* timer, take the closest one */
                auto &tm = timers.front();
                /* find its session */
                for (auto &sess: sessions) {
                    if (sess.uid != tm.uid) {
                        continue;
                    }
                    print_dbg("userservd: drop session %u", sess.uid);
                    /* notify errors; this will make clients close their
                     * connections, and once all of them are gone, the
                     * server can safely terminate it
                     */
                    for (auto c: sess.conns) {
                        msg_send(c, MSG_ERR);
                    }
                    break;
                }
                print_dbg("userservd: drop timer");
                timer_delete(tm.timer);
                timers.erase(timers.begin());
                goto signal_done;
            }
            /* this is a SIGCHLD */
            pid_t wpid;
            int status;
            print_dbg("userservd: sigchld");
            /* reap */
            while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
                /* deal with each pid here */
                if (!dinit_reaper(wpid)) {
                    std::fprintf(
                        stderr, "failed to restart dinit (%u)\n",
                        static_cast<unsigned int>(wpid)
                    );
                    /* this is an unrecoverable condition */
                    return 1;
                }
            }
        }
signal_done:
        /* check incoming connections on control socket */
        if (fds[1].revents) {
            for (;;) {
                auto afd = accept4(
                    fds[1].fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC
                );
                if (afd < 0) {
                    if (errno != EAGAIN) {
                        /* should not happen? disregard the connection */
                        perror("accept4 failed");
                    }
                    break;
                }
                auto &rfd = fds.emplace_back();
                rfd.fd = afd;
                rfd.events = POLLIN | POLLHUP;
                print_dbg("conn: accepted %d for %d", afd, fds[1].fd);
            }
        }
        /* check on pipes */
        for (i = 2; i < fds.size(); ++i) {
            if (fds[i].revents == 0) {
                continue;
            }
            /* find if this is a pipe */
            session *sess = nullptr;
            for (auto &sessr: sessions) {
                if (fds[i].fd == sessr.userpipe[0]) {
                    sess = &sessr;
                    break;
                }
            }
            if (!sess) {
                break;
            }
            if (fds[i].revents & POLLIN) {
                /* input on pipe or connection */
                struct sockaddr_un buf{};
                char *bufp = buf.sun_path;
                char *bufe = &buf.sun_path[sizeof(buf.sun_path) - 1];
                /* read the socket path */
                while (read(fds[i].fd, bufp++, 1) == 1) {
                    if (bufp == bufe) {
                        /* just in case, break off reading past the limit */
                        char b;
                        /* eat whatever else is in the pipe */
                        while (read(fds[i].fd, &b, 1) == 1) {}
                        break;
                    }
                }
                /* kill the pipe, we don't need it anymore */
                close(sess->userpipe[0]);
                close(sess->userpipe[1]);
                sess->userpipe[0] = -1;
                sess->userpipe[1] = -1;
                fds[i].fd = -1;
                fds[i].revents = 0;
                /* but error early if needed */
                if (!buf.sun_path[0]) {
                    perror("read failed");
                    continue;
                }
                /* wait for the boot service to come up */
                if (!dinit_boot(*sess, buf.sun_path)) {
                    /* this is an unrecoverable condition */
                    return 1;
                }
                continue;
            }
        }
        /* check on connections */
        for (; i < fds.size(); ++i) {
            if (fds[i].revents == 0) {
                continue;
            }
            if (fds[i].revents & POLLHUP) {
                conn_term(fds[i].fd);
                fds[i].fd = -1;
                fds[i].revents = 0;
                continue;
            }
            if (fds[i].revents & POLLIN) {
                /* input on connection */
                if (!handle_read(fds[i].fd)) {
                    fprintf(
                        stderr, "read: handler failed (terminate connection)\n"
                    );
                    conn_term(fds[i].fd);
                    fds[i].fd = -1;
                    fds[i].revents = 0;
                    continue;
                }
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
        if (!pipes.empty()) {
            fds.insert(fds.begin() + 2, pipes.begin(), pipes.end());
            pipes.clear();
        }
    }
    for (auto &fd: fds) {
        if (fd.fd >= 0) {
            close(fd.fd);
        }
    }
    return 0;
}
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
#include <limits>
#include <vector>
#include <algorithm>

#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "protocol.hh"

static bool debug = false;

/* session information: contains a list of connections (which also provide
 * a way to know when to end the session, as the connection is persistent
 * on the PAM side) and some statekeeping info:
 *
 * - the running service manager instance PID
 * - the user and group ID of the session's user
 * - a file descriptor for the dinit readiness notification FIFO
 * - whether dinit is currently waiting for readiness notificatio
 */
struct session {
    std::vector<int> conns{};
    char *homedir = nullptr;
    char dinit_tmp[6];
    pid_t dinit_pid = -1;
    unsigned int uid = 0;
    unsigned int gid = 0;
    int userpipe = -1;
    bool dinit_wait = true;

    ~session() {
        std::free(homedir);
    }
};

struct pending_conn {
    pending_conn(): pending_uid{1}, pending_gid{1}, pending_hdir{1} {}
    int conn = -1;
    char *homedir = nullptr;
    unsigned int uid = 0;
    unsigned int gid = 0;
    unsigned int hdirleft = 0;
    unsigned int hdirgot  = 0;
    unsigned int pending_uid: 1;
    unsigned int pending_gid: 1;
    unsigned int pending_hdir: 1;

    ~pending_conn() {
        std::free(homedir);
    }
};

static std::vector<session> sessions;
static std::vector<pending_conn> pending_conns;

/* file descriptors for poll */
static std::vector<pollfd> fds;
/* control IPC socket */
static int ctl_sock;
/* requests for new FIFOs; picked up by the event loop and cleared */
static std::vector<pollfd> fifos;

#define print_dbg(...) if (debug) { printf(__VA_ARGS__); }

static void dinit_clean(session &sess) {
    char buf[512];
    print_dbg("dinit: cleanup %u\n", sess.uid);
    /* close the fifo */
    if (sess.userpipe != -1) {
        std::snprintf(buf, sizeof(buf), USER_FIFO, sess.uid);
        print_dbg("dinit: close %s\n", buf);
        /* close best we can */
        static_cast<void>(close(sess.userpipe));
        static_cast<void>(unlink(buf));
        for (auto &pfd: fds) {
            if (pfd.fd == sess.userpipe) {
                pfd.fd = -1;
                pfd.revents = 0;
                break;
            }
        }
        sess.userpipe = -1;
    }
}

/* stop the dinit instance for a session */
static void dinit_stop(session &sess) {
    static constexpr int udig = std::numeric_limits<unsigned int>::digits10;
    /* temporary services dir */
    char buf[sizeof(USER_DIR) + udig + 5];
    print_dbg("dinit: stop\n");
    if (sess.dinit_pid != -1) {
        print_dbg("dinit: term\n");
        kill(sess.dinit_pid, SIGTERM);
        sess.dinit_pid = -1;
        sess.dinit_wait = true;
        dinit_clean(sess);
        /* remove the generated service directory best we can
         *
         * it would be pretty harmless to just leave it too
         */
        std::snprintf(buf, sizeof(buf), USER_DIR"/boot", sess.uid);
        std::memcpy(std::strstr(buf, "XXXXXX"), sess.dinit_tmp, 6);
        print_dbg("dinit: remove %s\n", buf);
        static_cast<void>(unlink(buf));
        *std::strrchr(buf, '/') = '\0';
        static_cast<void>(rmdir(buf));
    }
}

/* global service directory paths */
static constexpr char const *servpaths[] = {
    "/etc/dinit.d/user",
    "/usr/local/lib/dinit.d/user",
    "/usr/lib/dinit.d/user",
};

/* start the dinit instance for a session */
static bool dinit_start(session &sess) {
    static constexpr int udig = std::numeric_limits<unsigned int>::digits10;
    /* temporary services dir */
    char tdir[sizeof(USER_DIR) + udig];
    std::snprintf(tdir, sizeof(tdir), USER_DIR, sess.uid);
    /* create temporary services dir */
    if (!mkdtemp(tdir)) {
        perror("dinit: mkdtemp failed");
        return false;
    }
    print_dbg("dinit: created service directory (%s)\n", tdir);
    /* store the characters identifying the tempdir */
    std::memcpy(sess.dinit_tmp, tdir + std::strlen(tdir) - 6, 6);
    if (chown(tdir, sess.uid, sess.gid) < 0) {
        perror("dinit: chown failed");
        static_cast<void>(rmdir(tdir));
        return false;
    }
    /* user fifo path */
    char ufifo[sizeof(USER_FIFO) + udig];
    std::snprintf(ufifo, sizeof(ufifo), USER_FIFO, sess.uid);
    /* user services dir */
    char udir[HDIRLEN_MAX + 32];
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
        std::fprintf(f, "type = scripted\n");
        /* wait for a service directory */
        std::fprintf(f, "waits-for.d = %s/boot.d\n", udir);
        /* readiness notification */
        std::fprintf(f, "command = sh -c \"printf 1 > '%s'\"\n", ufifo);
        std::fclose(f);
        /* set perms otherwise we would infinite loop */
        if (chown(uboot, sess.uid, sess.gid) < 0) {
            perror("dinit: chown failed");
            static_cast<void>(unlink(uboot));
            return false;
        }
    }
    /* lazily set up user fifo */
    if (sess.userpipe == -1) {
        /* create a named pipe */
        static_cast<void>(unlink(ufifo));
        if (mkfifo(ufifo, 0600) < 0) {
            perror("dinit: mkfifo failed");
            return false;
        }
        /* user fifo is owned by the user */
        if (chown(ufifo, sess.uid, sess.gid) < 0) {
            perror("dinit: chown failed");
            static_cast<void>(unlink(ufifo));
            return false;
        }
        /* get its file descriptor */
        sess.userpipe = open(ufifo, O_RDONLY | O_NONBLOCK);
        if (sess.userpipe < 0) {
            perror("dinit: open failed");
            static_cast<void>(unlink(ufifo));
            return false;
        }
        auto &pfd = fifos.emplace_back();
        pfd.fd = sess.userpipe;
        pfd.events = POLLIN | POLLHUP;
    }
    /* launch dinit */
    print_dbg("dinit: launch\n");
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
        /* make up an environment, only need HOME */
        char uenv[HDIRLEN_MAX + 5];
        std::snprintf(uenv, sizeof(uenv), "HOME=%s", sess.homedir);
        char const *envp[] = {
            uenv, nullptr
        };
        /* 6 args reserved + whatever service dirs + terminator */
        char const *argp[6 + (sizeof(servpaths) / sizeof(*servpaths)) * 2 + 1];
        std::size_t cidx = 0;
        argp[cidx++] = "dinit";
        argp[cidx++] = "--user";
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
        /* fire */
        execvpe("dinit", const_cast<char **>(argp), const_cast<char **>(envp));
    } else if (pid < 0) {
        perror("dinit: fork failed");
        return false;
    }
    sess.dinit_pid = pid;
    return true;
}

/* restart callback for a PID: issued upon receiving a SIGCHLD
 *
 * this way the daemon supervises its session manager instances,
 * those that have a matching PID record in some existing session
 * will get restarted automatically
 */
static bool dinit_restart(pid_t pid) {
    print_dbg("dinit: check for restarts\n");
    for (auto &sess: sessions) {
        if (sess.dinit_pid != pid) {
            continue;
        }
        sess.dinit_pid = -1;
        if (!sess.dinit_wait) {
            /* failed without ever having signaled readiness
             * this indicates that we'd probably just loop forever,
             * so bail out
             */
             std::fprintf(stderr, "dinit: died without notifying readiness\n");
             return false;
        }
        sess.dinit_wait = true;
        return dinit_start(sess);
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
    print_dbg("msg: read %u (%d)\n", msg, fd);
    switch (msg) {
        case MSG_WELCOME: {
            /* new login, register it */
            auto &pc = pending_conns.emplace_back();
            pc.conn = fd;
            return msg_send(fd, MSG_OK);
        }
        case MSG_OK: {
            auto *sess = get_session(fd);
            if (!sess) {
                print_dbg("msg: no session for %u\n", msg);
                return msg_send(fd, MSG_ERR);
            }
            if (!sess->dinit_wait) {
                /* already started, reply with ok */
                print_dbg("msg: done\n");
                return msg_send(fd, MSG_OK_DONE);
            } else {
                if (sess->dinit_pid == -1) {
                    print_dbg("msg: start service manager\n");
                    if (!dinit_start(*sess)) {
                        return false;
                    }
                }
                msg = MSG_OK_WAIT;
                print_dbg("msg: wait\n");
                return msg_send(fd, MSG_OK_WAIT);
            }
            break;
        }
        default: {
            /* can be uid, gid, homedir size, or homedir data */
            for (
                auto it = pending_conns.begin();
                it != pending_conns.end(); ++it
            ) {
                if (it->conn == fd) {
                    /* first message after welcome */
                    if (it->pending_uid) {
                        print_dbg("msg: welcome uid %u\n", msg);
                        it->uid = msg;
                        it->pending_uid = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    /* first message after uid */
                    if (it->pending_gid) {
                        print_dbg(
                            "msg: welcome gid %u (uid %u)\n", msg, it->uid
                        );
                        it->gid = msg;
                        it->pending_gid = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    /* first message after gid */
                    if (it->pending_hdir) {
                        print_dbg(
                            "msg: getting homedir for %u (length: %u)\n",
                            it->uid, msg
                        );
                        /* no length or too long; reject */
                        if (!msg || (msg > HDIRLEN_MAX)) {
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                        it->homedir = static_cast<char *>(
                            std::malloc(msg + 1)
                        );
                        if (!it->homedir) {
                            print_dbg(
                                "msg: failed to alloc %u bytes for %u\n",
                                msg, it->uid
                            );
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                        it->hdirleft = msg;
                        it->pending_hdir = 0;
                        return msg_send(fd, MSG_OK);
                    }
                    /* any of the homedir pieces */
                    if (it->hdirleft) {
                        auto pkt = std::min(
                            static_cast<unsigned int >(sizeof(msg)),
                            it->hdirleft
                        );
                        std::memcpy(&it->homedir[it->hdirgot], &msg, pkt);
                        it->hdirgot += pkt;
                        it->hdirleft -= pkt;
                    }
                    /* not done receiving homedir yet */
                    if (it->hdirleft) {
                        return msg_send(fd, MSG_OK);
                    }
                    /* we have received all, sanitize the homedir */
                    {
                        it->homedir[it->hdirgot] = '\0';
                        auto hlen = std::strlen(it->homedir);
                        if (!hlen) {
                            return msg_send(fd, MSG_ERR);
                        }
                        while (it->homedir[hlen - 1] == '/') {
                            it->homedir[--hlen] = '\0';
                        }
                        if (!hlen) {
                            return msg_send(fd, MSG_ERR);
                        }
                    }
                    /* acknowledge the session */
                    print_dbg("msg: welcome %u (%s)\n", it->uid, it->homedir);
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
                                "msg: already have session %u\n", it->uid
                            );
                            pending_conns.erase(it);
                            return msg_send(fd, MSG_ERR);
                        }
                    }
                    print_dbg("msg: setup session %u\n", it->uid);
                    sess->conns.push_back(fd);
                    sess->uid = it->uid;
                    sess->gid = it->gid;
                    std::free(sess->homedir);
                    sess->homedir = it->homedir;
                    it->homedir = nullptr;
                    pending_conns.erase(it);
                    /* reply */
                    return msg_send(fd, MSG_OK);
                }
            }
            break;
        }
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
                "conn: close %d for session %u\n",
                conn, sess.uid
            );
            conv.erase(cit);
            /* empty now; shut down session */
            if (conv.empty()) {
                dinit_stop(sess);
                sess.dinit_pid = -1;
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

    print_dbg("socket: created %d for %s\n", sock, path);

    sockaddr_un un;
    std::memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;

    auto plen = strlen(path);
    if (plen >= sizeof(un.sun_path)) {
        std::fprintf(stderr, "path name %s too long", path);
        close(sock);
        return false;
    }

    std::memcpy(un.sun_path, path, plen + 1);
    /* no need to check this */
    static_cast<void>(unlink(path));

    if (bind(sock, reinterpret_cast<sockaddr const *>(&un), sizeof(un)) < 0) {
        perror("bind failed");
        close(sock);
        return false;
    }
    print_dbg("socket: bound %d for %s\n", sock, path);

    if (chmod(path, 0600) < 0) {
        perror("chmod failed");
        goto fail;
    }
    print_dbg("socket: permissions set\n");

    if (listen(sock, SOMAXCONN) < 0) {
        perror("listen failed");
        goto fail;
    }
    print_dbg("socket: listen\n");

    print_dbg("socket: done\n");
    return true;

fail:
    static_cast<void>(unlink(path));
    close(sock);
    return false;
}

int main() {
    if (signal(SIGCHLD, sighandler) == SIG_ERR) {
        perror("signal failed");
    }

    /* prealloc a bunch of space */
    pending_conns.reserve(8);
    sessions.reserve(16);
    fds.reserve(64);
    fifos.reserve(8);

    if (std::getenv("DINIT_USERSERVD_DEBUG")) {
        debug = true;
    }

    print_dbg("userservd: init signal fd\n");

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

    print_dbg("userservd: init control socket\n");

    /* main control socket */
    {
        if (!sock_new(DAEMON_SOCK, ctl_sock)) {
            return 1;
        }
        auto &pfd = fds.emplace_back();
        pfd.fd = ctl_sock;
        pfd.events = POLLIN;
    }

    print_dbg("userservd: main loop\n");

    std::size_t i = 0;

    /* main loop */
    for (;;) {
        print_dbg("userservd: poll\n");
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
            /* this is a SIGCHLD (only registered handler) */
            pid_t wpid;
            int status;
            print_dbg("userservd: sigchld\n");
            /* reap */
            while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
                /* deal with each dinit pid here */
                if (!dinit_restart(wpid)) {
                    std::fprintf(
                        stderr, "failed to restart dinit (%u)\n",
                        static_cast<unsigned int>(wpid)
                    );
                    /* this is an unrecoverable condition */
                    return 1;
                }
            }
        }
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
                print_dbg("conn: accepted %d for %d\n", afd, fds[1].fd);
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
                if (fds[i].fd == sessr.userpipe) {
                    sess = &sessr;
                    break;
                }
            }
            if (!sess) {
                break;
            }
            if (fds[i].revents & POLLIN) {
                /* input on pipe or connection */
                char b;
                /* get a byte */
                if (read(fds[i].fd, &b, 1) == 1) {
                    /* notify session and clear dinit for wait */
                    if (sess->dinit_wait) {
                        print_dbg("dinit: ready notification\n");
                        unsigned int msg = MSG_OK_DONE;
                        for (auto c: sess->conns) {
                            if (send(c, &msg, sizeof(msg), 0) < 0) {
                                perror("conn: send failed");
                            }
                        }
                        sess->dinit_wait = false;
                    } else {
                        /* spurious, warn and eat it */
                        fprintf(stderr, "fifo: got data but not waiting");
                    }
                } else {
                    perror("read failed");
                    continue;
                }
                /* eat whatever else is in the pipe */
                while (read(fds[i].fd, &b, 1) == 1) {}
            }
            if (fds[i].revents & POLLHUP) {
                dinit_clean(*sess);
                fds[i].fd = -1;
                fds[i].revents = 0;
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
        /* queue fifos after control socket */
        if (!fifos.empty()) {
            fds.insert(fds.begin() + 2, fifos.begin(), fifos.end());
            fifos.clear();
        }
    }
    for (auto &fd: fds) {
        if (fd.fd >= 0) {
            close(fd.fd);
        }
    }
    return 0;
}
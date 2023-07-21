/* shared turnstiled header
 *
 * Copyright 2022 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef TURNSTILED_HH
#define TURNSTILED_HH

#include <cstddef>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "protocol.hh"

struct login;

/* represents a single session within a login */
struct session {
    session():
        str_left{0},
        handshake{1},
        pend_vtnr{1},
        pend_remote{1},
        pend_service{1},
        pend_type{1},
        pend_class{1},
        pend_desktop{1},
        pend_seat{1},
        pend_tty{1},
        pend_display{1},
        pend_ruser{1},
        pend_rhost{1}
    {}
    /* data strings */
    std::string s_service{};
    std::string s_type{};
    std::string s_class{};
    std::string s_desktop{};
    std::string s_seat{};
    std::string s_tty{};
    std::string s_display{};
    std::string s_ruser{};
    std::string s_rhost{};
    /* the login the session belongs to */
    login *lgn;
    /* session id */
    unsigned long id;
    /* the session vt number */
    unsigned long vtnr;
    /* pid of the login process */
    pid_t lpid;
    /* requested amount of data before we can proceed */
    int needed;
    /* whether we're remote */
    bool remote;
    /* the connection descriptor */
    int fd;
    /* stage */
    unsigned int str_left: 16;
    unsigned int handshake: 1;
    unsigned int pend_vtnr: 1;
    unsigned int pend_remote: 1;
    unsigned int pend_service: 1;
    unsigned int pend_type: 1;
    unsigned int pend_class: 1;
    unsigned int pend_desktop: 1;
    unsigned int pend_seat: 1;
    unsigned int pend_tty: 1;
    unsigned int pend_display: 1;
    unsigned int pend_ruser: 1;
    unsigned int pend_rhost: 1;
};

/* represents a collection of sessions for a specific user id */
struct login {
    /* a list of connection file descriptors for this login */
    std::vector<session> sessions{};
    /* the username */
    std::string username{};
    /* the string the backend 'run' hands over to 'ready' */
    std::string srvstr{};
    /* the user's shell */
    std::string shell{};
    /* the user's home directory */
    std::string homedir{};
    /* the XDG_RUNTIME_DIR */
    std::string rundir{};
    /* the PID of the service manager process we are currently managing */
    pid_t srv_pid = -1;
    /* the PID of the backend "ready" process that reports final readiness */
    pid_t start_pid = -1;
    /* the PID of the service manager process that is currently dying */
    pid_t term_pid = -1;
    /* login timer; there can be only one per login */
    timer_t timer{};
    sigevent timer_sev{};
    /* user and group IDs read off the first connection */
    unsigned int uid = 0;
    unsigned int gid = 0;
    /* the read end of the pipe that the service manager uses to signal
     * command readiness
     */
    int userpipe = -1;
    /* login directory descriptor */
    int dirfd = -1;
    /* whether the login should be repopulated on next session */
    bool repopulate = true;
    /* true unless srv_pid has completely finished starting */
    bool srv_wait = true;
    /* false unless waiting for term_pid to quit before starting again */
    bool srv_pending = false;
    /* whether to manage XDG_RUNTIME_DIR (typically false) */
    bool manage_rdir = false;
    /* whether the timer is actually currently set up */
    bool timer_armed = false;
    /* whether a SIGKILL was attempted */
    bool kill_tried = false;
    /* whether a pipe is queued */
    bool pipe_queued = false;

    login();
    void remove_sdir();
    bool arm_timer(std::time_t);
    void disarm_timer();
};

/* filesystem utilities */
int dir_make_at(int dfd, char const *dname, mode_t mode);
bool rundir_make(char *rundir, unsigned int uid, unsigned int gid);
void rundir_clear(char const *rundir);
bool dir_clear_contents(int dfd);

/* config file related utilities */
void cfg_read(char const *cfgpath);
void cfg_expand_rundir(
    std::string &dest, char const *tmpl, unsigned int uid, unsigned int gid
);

/* service manager utilities */
void srv_child(login &sess, char const *backend, bool d);
bool srv_boot(login &sess, char const *backend);

struct cfg_data {
    time_t login_timeout = 60;
    bool debug = false;
    bool disable = false;
    bool debug_stderr = false;
    bool manage_rdir = MANAGE_RUNDIR;
    bool export_dbus = true;
    bool linger = false;
    bool linger_never = false;
    std::string backend = "dinit";
    std::string rdir_path = RUN_PATH "/user/%u";
};

extern cfg_data *cdata;

/* these are macros for a simple reason; making them functions will trigger
 * format-security warnings (even though it's technically always safe for
 * us, there is no way to bypass that portably) and making it a C-style
 * vararg function is not possible (because vsyslog is not standard)
 *
 * in a macro we just pass things through, so it's completely safe
 */

#define print_dbg(...) \
    if (cdata->debug) { \
        if (cdata->debug_stderr) { \
            fprintf(stderr, __VA_ARGS__); \
            fputc('\n', stderr); \
        } \
        syslog(LOG_DEBUG, __VA_ARGS__); \
    }

#define print_err(...) \
    if (cdata->debug_stderr) { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
    } \
    syslog(LOG_ERR, __VA_ARGS__);

#endif

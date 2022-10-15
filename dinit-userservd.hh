/* shared dinit-userservd header
 *
 * Copyright 2022 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef DINIT_USERSERVD_HH
#define DINIT_USERSERVD_HH

#include <cstddef>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "protocol.hh"

/* represents a collection of logins for a specific user id */
struct session {
    /* a list of connection file descriptors for this session */
    std::vector<int> conns{};
    /* home directory path received from the PAM module */
    char *homedir = nullptr;
    /* points to a place within csock, used to keep track
     * when reading the socket path off the userpipe
     */
    char *sockptr = nullptr;
    /* the PID of the dinit process we are currently managing */
    pid_t dinit_pid = -1;
    /* the PID of the dinitctl process that reports final readiness */
    pid_t start_pid = -1;
    /* the PID of the dinit process that is currently dying */
    pid_t term_pid = -1;
    /* session timer; there can be only one per session */
    timer_t timer{};
    sigevent timer_sev{};
    /* user and group IDs read off the first connection */
    unsigned int uid = 0;
    unsigned int gid = 0;
    /* the read end of the pipe that dinit uses to signal command readiness */
    int userpipe = -1;
    /* session directory descriptor */
    int dirfd = -1;
    /* true unless dinit_pid has completely finished starting */
    bool dinit_wait = true;
    /* false unless waiting for term_pid to quit before starting again */
    bool dinit_pending = false;
    /* whether to manage XDG_RUNTIME_DIR (typically false) */
    bool manage_rdir = false;
    /* whether the timer is actually currently set up */
    bool timer_armed = false;
    /* whether a SIGKILL was attempted */
    bool kill_tried = false;
    /* whether a pipe is queued */
    bool pipe_queued = false;
    /* XDG_RUNTIME_DIR path, regardless of if managed or not */
    char rundir[DIRLEN_MAX];
    /* dinit control socket path, read off userpipe */
    char csock[sizeof(sockaddr_un{}.sun_path)];
    /* string versions of uid and gid */
    char uids[32], gids[32];

    session();
    ~session();
    void remove_sdir();
    bool arm_timer(std::time_t);
    void disarm_timer();
};

/* filesystem utilities */
int dir_make_at(int dfd, char const *dname, mode_t mode);
bool rundir_make(char *rundir, unsigned int uid, unsigned int gid);
void rundir_clear(char *rundir);
bool dir_clear_contents(int dfd);

/* config file related utilities */
void cfg_read(char const *cfgpath);
bool cfg_expand_rundir(
    char *dest, std::size_t destsize, char const *tmpl,
    char const *uid, char const *gid
);
void cfg_populate_srvdirs();

/* dinit utilities */
void dinit_child(session &sess, char const *pipenum);
bool dinit_boot(session &sess, bool disabled);

struct cfg_data {
    time_t dinit_timeout = 60;
    bool debug = false;
    bool disable = false;
    bool debug_stderr = false;
    bool manage_rdir = false;
    bool export_dbus = true;
    std::string rdir_path = RUN_PATH "/user/%u";
    std::string boot_path = ".config/dinit.d/boot.d";
    std::vector<std::string> srv_paths{};
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

/* shared dinit-userservd header
 *
 * Copyright 2022 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef DINIT_USERSERVD_HH
#define DINIT_USERSERVD_HH

#include <cstddef>
#include <cstdio>
#include <string>
#include <vector>

#include <syslog.h>
#include <sys/stat.h>

#include "protocol.hh"

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
    char *sockptr = nullptr;
    pid_t dinit_pid = -1;
    pid_t start_pid = -1;
    pid_t term_pid = -1;
    unsigned int uid = 0;
    unsigned int gid = 0;
    int userpipe = -1;
    int dirfd = -1;
    bool dinit_wait = true;
    bool manage_rdir = false;
    char rundir[DIRLEN_MAX];
    char csock[sizeof(sockaddr_un{}.sun_path)];
    char uids[32], gids[32];

    session() {
        sockptr = csock;
    }

    ~session();
    void remove_sdir();
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
bool dinit_boot(session &sess);

struct cfg_data {
    time_t dinit_timeout = 60;
    bool debug = false;
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

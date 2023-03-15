#include <cstring>

#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <unistd.h>
#include <paths.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "turnstiled.hh"

#include <sys/resource.h>
#include <security/pam_appl.h>
#ifdef HAVE_PAM_MISC
#  include <security/pam_misc.h>
#  define PAM_CONV_FUNC misc_conv
#else
#  include <security/openpam.h>
#  define PAM_CONV_FUNC openpam_ttyconv
#endif

bool srv_boot(session &sess, char const *backend) {
    print_dbg("srv: startup wait");
    auto pid = fork();
    if (pid < 0) {
        print_err("srv: fork failed (%s)", strerror(errno));
        /* unrecoverable */
        return false;
    }
    if (pid != 0) {
        /* parent process */
        sess.start_pid = pid;
        return true;
    }
    if (!backend) {
        /* if service manager is not managed, simply succeed immediately */
        exit(0);
        return true;
    }
    /* child process */
    if (getuid() == 0) {
        if (setgid(sess.gid) != 0) {
            print_err("srv: failed to set gid (%s)", strerror(errno));
            exit(1);
        }
        if (setuid(sess.uid) != 0) {
            print_err("srv: failed to set uid (%s)", strerror(errno));
            exit(1);
        }
    }
    char buf[sizeof(LIBEXEC_PATH) + 128];
    std::snprintf(buf, sizeof(buf), LIBEXEC_PATH "/%s", backend);
    /* invoke shebangless to match "run" */
    char const *arg0 = _PATH_BSHELL;
    char const *rsl = std::strrchr(arg0, '/');
    if (rsl) {
        arg0 = rsl + 1;
    }
    execl(_PATH_BSHELL, arg0, buf, "ready", sess.srvstr.data(), nullptr);
    exit(1);
    return true;
}

static bool dpam_setup_groups(pam_handle_t *pamh, session const &sess) {
    if (initgroups(sess.username.data(), sess.gid) != 0) {
        perror("srv: failed to set supplementary groups");
        return false;
    }
    auto pst = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (pst != PAM_SUCCESS) {
        perror("srv: pam_setcred");
        pam_end(pamh, pst);
        return false;
    }
    return true;
}

static pam_handle_t *dpam_begin(session const &sess) {
    pam_conv cnv = {
        PAM_CONV_FUNC,
        nullptr
    };
    pam_handle_t *pamh = nullptr;
    auto pst = pam_start(DPAM_SERVICE, sess.username.data(), &cnv, &pamh);
    if (pst != PAM_SUCCESS) {
        perror("srv: pam_start");
        return nullptr;
    }
    /* set the originating user while at it */
    pst = pam_set_item(pamh, PAM_RUSER, "root");
    if (pst != PAM_SUCCESS) {
        perror("srv: pam_set_item(PAM_RUSER)");
        pam_end(pamh, pst);
        return nullptr;
    }
    if (!dpam_setup_groups(pamh, sess)) {
        return nullptr;
    }
    return pamh;
}

static void sanitize_limits() {
    struct rlimit l{0, 0};

    setrlimit(RLIMIT_NICE, &l);
    setrlimit(RLIMIT_RTPRIO, &l);

    l.rlim_cur = RLIM_INFINITY;
    l.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_FSIZE, &l);
    setrlimit(RLIMIT_AS, &l);

    getrlimit(RLIMIT_NOFILE, &l);
    if (l.rlim_cur != FD_SETSIZE) {
        l.rlim_cur = FD_SETSIZE;
        setrlimit(RLIMIT_NOFILE, &l);
    }
}

static bool dpam_open(pam_handle_t *pamh) {
    /* before opening session, do not rely on just PAM and sanitize a bit */
    sanitize_limits();

    auto pst = pam_open_session(pamh, 0);
    if (pst != PAM_SUCCESS) {
        perror("srv: pam_open_session");
        pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
        pam_end(pamh, pst);
        return false;
    }
    return true;
}

static bool dpam_setup(pam_handle_t *pamh, session const &sess) {
    if (!pamh) {
        return false;
    }
    if (!dpam_open(pamh)) {
        return false;
    }
    /* change identity */
    if (setgid(sess.gid) != 0) {
        perror("srv: failed to set gid");
        return false;
    }
    if (setuid(sess.uid) != 0) {
        perror("srv: failed to set uid");
        return false;
    }
    return true;
}

static void dpam_finalize(pam_handle_t *pamh) {
    if (!pamh) {
        /* when not doing PAM, at least restore umask to user default,
         * otherwise the PAM configuration will do it (pam_umask.so)
         */
        umask(022);
        return;
    }
    /* end with success */
    pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT);
}

void srv_child(session &sess, char const *backend, char const *pipenum) {
    pam_handle_t *pamh = nullptr;
    if (getuid() == 0) {
        /* setup pam session */
        pamh = dpam_begin(sess);
        if (!dpam_setup(pamh, sess)) {
            return;
        }
    }
    /* change directory to home, fall back to / or error */
    if ((chdir(sess.homedir) < 0) || (chdir("/") < 0)) {
        perror("srv: failed to change directory");
    }
    /* set up service manager tempdir after we drop privileges */
    char tdirn[38];
    std::snprintf(
        tdirn, sizeof(tdirn), "srv.%lu",
        static_cast<unsigned long>(getpid())
    );
    int tdirfd = dir_make_at(sess.dirfd, tdirn, 0700);
    if (tdirfd < 0) {
        perror("srv: failed to create state dir");
        return;
    }
    close(tdirfd);
    /* build up env and args list */
    std::vector<char> execs{};
    std::size_t argc = 0, nexec = 0;
    auto add_str = [&execs, &nexec](auto &&...s) {
        (execs.insert(execs.end(), s, s + std::strlen(s)), ...);
        execs.push_back('\0');
        ++nexec;
    };
    /* argv starts here; we run a "login shell" */
    char const *arg0 = _PATH_BSHELL;
    char const *rsl = std::strrchr(arg0, '/');
    if (rsl) {
        arg0 = rsl + 1;
    }
    add_str("-", arg0);
    /* path to run script */
    add_str(LIBEXEC_PATH, "/", backend);
    /* arg1: action */
    add_str("run");
    /* arg1: ready_fd */
    add_str(pipenum);
    /* arg2: srvdir */
    add_str(RUN_PATH, "/", SOCK_DIR, "/", sess.uids, "/", tdirn);
    /* arg3: confdir */
    add_str(CONF_PATH, "/backend");
    argc = nexec;
    /* pam env vars take preference */
    bool have_env_shell   = false, have_env_user   = false,
         have_env_logname = false, have_env_home   = false,
         have_env_uid     = false, have_env_gid    = false,
         have_env_path    = false, have_env_rundir = false;
    /* get them and loop */
    if (pamh) {
        /* this is a copy, but we exec so it's fine to leak */
        char **penv = pam_getenvlist(pamh);
        while (penv && *penv) {
            /* ugly but it's not like putenv actually does anything else */
            if (!strncmp(*penv, "SHELL=", 6)) {
                have_env_shell = true;
            } else if (!strncmp(*penv, "USER=", 5)) {
                have_env_user = true;
            } else if (!strncmp(*penv, "LOGNAME=", 8)) {
                have_env_logname = true;
            } else if (!strncmp(*penv, "HOME=", 5)) {
                have_env_home = true;
            } else if (!strncmp(*penv, "UID=", 4)) {
                have_env_uid = true;
            } else if (!strncmp(*penv, "GID=", 4)) {
                have_env_gid = true;
            } else if (!strncmp(*penv, "PATH=", 5)) {
                have_env_path = true;
            } else if (!strncmp(*penv, "XDG_RUNTIME_DIR=", 16)) {
                have_env_rundir = true;
            }
            add_str(*penv);
        }
    }
    /* add our environment defaults if not already set */
    if (!have_env_shell) {
        add_str("SHELL=" _PATH_BSHELL);
    }
    if (!have_env_user) {
        add_str("USER=", sess.username.data());
    }
    if (!have_env_logname) {
        add_str("LOGNAME=", sess.username.data());
    }
    if (!have_env_home) {
        add_str("HOME=", sess.homedir);
    }
    if (!have_env_uid) {
        add_str("UID=", sess.uids);
    }
    if (!have_env_gid) {
        add_str("GID=", sess.gids);
    }
    if (!have_env_path) {
        add_str("PATH=" _PATH_DEFPATH);
    }
    if (sess.rundir[0] && !have_env_rundir) {
        add_str("XDG_RUNTIME_DIR=", sess.rundir);
    }
    /* make up env and arg arrays */
    std::vector<char const *> argp{};
    {
        char const *execsp = execs.data();
        argp.reserve(nexec + 2);
        for (std::size_t i = 0; i < argc; ++i) {
            argp.push_back(execsp);
            execsp += std::strlen(execsp) + 1;
        }
        argp.push_back(nullptr);
        for (std::size_t i = argc; i < nexec; ++i) {
            argp.push_back(execsp);
            execsp += std::strlen(execsp) + 1;
        }
        argp.push_back(nullptr);
    }
    /* finish pam before execing */
    dpam_finalize(pamh);
    /* fire */
    auto *argv = const_cast<char **>(&argp[0]);
    execve(_PATH_BSHELL, argv, argv + argc + 1);
}

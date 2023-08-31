#include <cstring>

#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <paths.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

static bool exec_script(
    char const *backend, char const *arg, char const *data,
    unsigned int uid, unsigned int gid, pid_t &outpid
) {
    auto pid = fork();
    if (pid < 0) {
        /* unrecoverable */
        return false;
    }
    if (pid != 0) {
        /* parent process */
        outpid = pid;
        return true;
    }
    if (!backend) {
        /* if service manager is not managed, simply succeed immediately */
        exit(0);
        return true;
    }
    /* child process */
    if (getuid() == 0) {
        if (setgid(gid) != 0) {
            perror("srv: failed to set gid");
            exit(1);
        }
        if (setuid(uid) != 0) {
            perror("srv: failed to set uid");
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
    execl(_PATH_BSHELL, arg0, buf, arg, data, nullptr);
    exit(1);
    return true;
}

bool srv_boot(login &lgn, char const *backend) {
    print_dbg("srv: startup (ready)");
    if (!exec_script(
        backend, "ready", lgn.srvstr.data(), lgn.uid, lgn.gid, lgn.start_pid
    )) {
        print_err("srv: fork failed (%s)", strerror(errno));
        return false;
    }
    return true;
}

static bool dpam_setup_groups(
    pam_handle_t *pamh, char const *user, unsigned int gid
) {
    if (initgroups(user, gid) != 0) {
        perror("srv: failed to set supplementary groups");
        return false;
    }
    auto pst = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (pst != PAM_SUCCESS) {
        fprintf(stderr, "srv: pam_setcred: %s", pam_strerror(pamh, pst));
        pam_end(pamh, pst);
        return false;
    }
    return true;
}

static pam_handle_t *dpam_begin(char const *user, unsigned int gid) {
    pam_conv cnv = {
        PAM_CONV_FUNC,
        nullptr
    };
    pam_handle_t *pamh = nullptr;
    auto pst = pam_start(DPAM_SERVICE, user, &cnv, &pamh);
    if (pst != PAM_SUCCESS) {
        fprintf(stderr, "srv: pam_start: %s", pam_strerror(pamh, pst));
        return nullptr;
    }
    if (!dpam_setup_groups(pamh, user, gid)) {
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
    if (!pamh) {
        return false;
    }

    /* before opening session, do not rely on just PAM and sanitize a bit */
    sanitize_limits();

    auto pst = pam_open_session(pamh, 0);
    if (pst != PAM_SUCCESS) {
        fprintf(stderr, "srv: pam_open_session: %s", pam_strerror(pamh, pst));
        pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
        pam_end(pamh, pst);
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

static int sigpipe[2] = {-1, -1};

static void sig_handler(int sign) {
    write(sigpipe[1], &sign, sizeof(sign));
}

static void fork_and_wait(
    pam_handle_t *pamh, char const *backend,
    unsigned int uid, unsigned int gid
) {
    int pst, status;
    int term_count = 0;
    struct pollfd pfd;
    struct sigaction sa{};
    sigset_t mask;
    pid_t p;
    /* set up event loop bits, before fork for simpler cleanup */
    if (pipe(sigpipe) < 0) {
        perror("srv: pipe failed");
        goto fail;
    }
    pfd.fd = sigpipe[0];
    pfd.events = POLLIN;
    pfd.revents = 0;
    /* fork */
    p = fork();
    if (p == 0) {
        /* child, return to exec */
        close(sigpipe[0]);
        close(sigpipe[1]);
        return;
    } else if (p < 0) {
        perror("srv: fork failed");
        goto fail;
    }
    /* ignore signals */
    sigfillset(&mask);
    sigdelset(&mask, SIGTERM);
    sigdelset(&mask, SIGCHLD);
    sigprocmask(SIG_SETMASK, &mask, nullptr);
    /* set up handlers for non-ignored signals */
    sa.sa_handler = sig_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    /* our own little event loop */
    for (;;) {
        auto pret = poll(&pfd, 1, -1);
        if (pret < 0) {
            /* interrupted by signal */
            if (errno == EINTR) {
                continue;
            }
            perror("srv: poll failed");
            goto fail;
        } else if (pret == 0) {
            continue;
        }
        int sign;
        if (read(pfd.fd, &sign, sizeof(sign)) != sizeof(sign)) {
            perror("srv: signal read failed");
            goto fail;
        }
        if (sign == SIGTERM) {
            char buf[32];
            pid_t outp;
            int st;
            if ((term_count++ > 1) || !backend) {
                /* hard kill */
                kill(p, SIGKILL);
                continue;
            }
            std::snprintf(buf, sizeof(buf), "%zu", size_t(p));
            /* otherwise run the stop part */
            if (!exec_script(backend, "stop", buf, uid, gid, outp)) {
                /* failed? */
                perror("srv: stop exec failed, fall back to TERM");
                kill(p, SIGTERM);
            }
            /* wait for it to end */
            do {
                pid_t w = waitpid(outp, &st, 0);
                if (w < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    perror("srv: stop exec wait failed");
                    break;
                }
            } while (!WIFEXITED(st) && !WIFSIGNALED(st));
            continue;
        }
        /* SIGCHLD */
        int wpid;
        while ((wpid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (wpid != p) {
                continue;
            }
            goto done;
        }
    }
done:
    /* close session */
    if (!pamh) {
        goto estatus;
    }
    pst = pam_close_session(pamh, 0);
    if (pst != PAM_SUCCESS) {
        fprintf(stderr, "srv: pam_close_session: %s", pam_strerror(pamh, pst));
        pam_end(pamh, pst);
        goto fail;
    }
    /* finalize */
    pam_setcred(pamh, PAM_DELETE_CRED);
    pam_end(pamh, PAM_SUCCESS);
estatus:
    /* propagate exit status */
    exit(WIFEXITED(status) ? WEXITSTATUS(status) : (WTERMSIG(status) + 128));
fail:
    exit(1);
}

/* dummy "service manager" child process with none backend */
static void srv_dummy() {
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

void srv_child(login &lgn, char const *backend) {
    pam_handle_t *pamh = nullptr;
    bool is_root = (getuid() == 0);
    /* create a new session */
    if (setsid() < 0) {
        perror("srv: setsid failed");
    }
    /* begin pam session setup */
    if (is_root) {
        pamh = dpam_begin(lgn.username.data(), lgn.gid);
        if (!dpam_open(pamh)) {
            return;
        }
    }
    /* handle the parent/child logic here
     * if we're forking, only child makes it past this func
     */
    fork_and_wait(pamh, backend, lgn.uid, lgn.gid);
    /* drop privs */
    if (is_root) {
        /* change identity */
        if (setgid(lgn.gid) != 0) {
            perror("srv: failed to set gid");
            return;
        }
        if (setuid(lgn.uid) != 0) {
            perror("srv: failed to set uid");
            return;
        }
    }
    /* dummy service manager if requested */
    if (!backend) {
        srv_dummy();
        return;
    }
    /* change directory to home, fall back to / or error */
    if ((chdir(lgn.homedir.data()) < 0) || (chdir("/") < 0)) {
        perror("srv: failed to change directory");
        return;
    }
    /* set up service manager tempdir after we drop privileges */
    char tdirn[38];
    std::snprintf(
        tdirn, sizeof(tdirn), "srv.%lu",
        static_cast<unsigned long>(getpid())
    );
    int tdirfd = dir_make_at(lgn.dirfd, tdirn, 0700);
    if (tdirfd < 0) {
        perror("srv: failed to create state dir");
        return;
    }
    close(tdirfd);
    /* stringify the uid/gid */
    char uidbuf[32], gidbuf[32];
    std::snprintf(uidbuf, sizeof(uidbuf), "%u", lgn.uid);
    std::snprintf(gidbuf, sizeof(gidbuf), "%u", lgn.gid);
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
    /* arg1: ready pipe */
    add_str(RUN_PATH, "/", SOCK_DIR, "/", uidbuf, "/ready");
    /* arg2: srvdir */
    add_str(RUN_PATH, "/", SOCK_DIR, "/", uidbuf, "/", tdirn);
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
            add_str(*penv++);
        }
    }
    /* add our environment defaults if not already set */
    if (!have_env_shell) {
        add_str("SHELL=", lgn.shell.data());
    }
    if (!have_env_user) {
        add_str("USER=", lgn.username.data());
    }
    if (!have_env_logname) {
        add_str("LOGNAME=", lgn.username.data());
    }
    if (!have_env_home) {
        add_str("HOME=", lgn.homedir.data());
    }
    if (!have_env_uid) {
        add_str("UID=", uidbuf);
    }
    if (!have_env_gid) {
        add_str("GID=", gidbuf);
    }
    if (!have_env_path) {
        add_str("PATH=" _PATH_DEFPATH);
    }
    if (!lgn.rundir.empty() && !have_env_rundir) {
        add_str("XDG_RUNTIME_DIR=", lgn.rundir.data());
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

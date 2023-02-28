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

bool dinit_boot(session &sess, bool disabled) {
    print_dbg("dinit: boot wait");
    auto pid = fork();
    if (pid < 0) {
        print_err("dinit: fork failed (%s)", strerror(errno));
        /* unrecoverable */
        return false;
    }
    if (pid != 0) {
        /* parent process */
        sess.start_pid = pid;
        return true;
    }
    if (disabled) {
        /* if dinit is not managed, simply succeed immediately */
        exit(0);
        return true;
    }
    /* child process */
    if (getuid() == 0) {
        if (setgid(sess.gid) != 0) {
            print_err("dinit: failed to set gid (%s)", strerror(errno));
            exit(1);
        }
        if (setuid(sess.uid) != 0) {
            print_err("dinit: failed to set uid (%s)", strerror(errno));
            exit(1);
        }
    }
    execlp(
        "dinitctl", "dinitctl",
        "--socket-path", sess.csock, "start", "boot", nullptr
    );
    exit(1);
    return true;
}

static bool dpam_setup_groups(pam_handle_t *pamh, struct passwd *pwd) {
    if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
        perror("dinit: failed to set supplementary groups");
        return false;
    }
    auto pst = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (pst != PAM_SUCCESS) {
        perror("dinit: pam_setcred");
        pam_end(pamh, pst);
        return false;
    }
    return true;
}

static pam_handle_t *dpam_begin(struct passwd *pwd) {
    pam_conv cnv = {
        PAM_CONV_FUNC,
        nullptr
    };
    pam_handle_t *pamh = nullptr;
    auto pst = pam_start(DPAM_SERVICE, pwd->pw_name, &cnv, &pamh);
    if (pst != PAM_SUCCESS) {
        perror("dinit: pam_start");
        return nullptr;
    }
    /* set the originating user while at it */
    pst = pam_set_item(pamh, PAM_RUSER, "root");
    if (pst != PAM_SUCCESS) {
        perror("dinit: pam_set_item(PAM_RUSER)");
        pam_end(pamh, pst);
        return nullptr;
    }
    if (!dpam_setup_groups(pamh, pwd)) {
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
        perror("dinit: pam_open_session");
        pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
        pam_end(pamh, pst);
        return false;
    }
    return true;
}

static bool dpam_setup(pam_handle_t *pamh, struct passwd *pwd) {
    if (!dpam_open(pamh)) {
        return false;
    }
    /* change identity */
    if (setgid(pwd->pw_uid) != 0) {
        perror("dinit: failed to set gid");
        return false;
    }
    if (setuid(pwd->pw_gid) != 0) {
        perror("dinit: failed to set uid");
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

void dinit_child(session &sess, char const *pipenum) {
    auto *pw = getpwuid(sess.uid);
    if (!pw) {
        perror("dinit: getpwuid failed");
        return;
    }
    if ((pw->pw_uid != sess.uid) || (pw->pw_gid != sess.gid)) {
        fputs("dinit: uid/gid does not match user", stderr);
        return;
    }
    pam_handle_t *pamh = nullptr;
    if (getuid() == 0) {
        /* setup pam session */
        pamh = dpam_begin(pw);
        if (!pamh || !dpam_setup(pamh, pw)) {
            return;
        }
    }
    /* set up dinit tempdir after we drop privileges */
    char tdirn[38];
    std::snprintf(
        tdirn, sizeof(tdirn), "dinit.%lu",
        static_cast<unsigned long>(getpid())
    );
    int tdirfd = dir_make_at(sess.dirfd, tdirn, 0700);
    if (tdirfd < 0) {
        perror("dinit: failed to create dinit dir");
        return;
    }
    /* set up service files */
    {
        auto bfd = openat(tdirfd, "boot", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (bfd < 0) {
            perror("dinit: openat failed");
            return;
        }
        /* reopen as a real file handle, now owns bfd */
        auto *f = fdopen(bfd, "w");
        if (!f) {
            perror("dinit: fdopen failed");
            return;
        }
        /* write boot service */
        std::fprintf(f, "type = internal\n");
        /* system service dependency */
        std::fprintf(f, "depends-on = system\n");
        /* wait for a service directory */
        std::fprintf(
            f, "waits-for.d = %s/%s\n", sess.homedir,
            cdata->boot_path.data()
        );
        std::fclose(f);
        /* now system */
        bfd = openat(tdirfd, "system", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (bfd < 0) {
            perror("dinit: openat failed");
            return;
        }
        /* ditto */
        f = fdopen(bfd, "w");
        if (!f) {
            perror("dinit: fdopen failed");
            return;
        }
        /* this is also internal */
        std::fprintf(f, "type = internal\n");
        /* wait for system service directory */
        std::fprintf(f, "waits-for.d = %s\n", cdata->sys_boot_path.data());
        std::fclose(f);
    }
    /* create boot path, if possible; if it fails, it fails (harmless-ish) */
    int hfd = open(sess.homedir, O_RDONLY);
    if (struct stat hstat; !fstat(hfd, &hstat) && S_ISDIR(hstat.st_mode)) {
        char *bptr = &cdata->boot_path[0];
        /* boot dir already exists */
        if (!fstatat(hfd, bptr, &hstat, 0) && S_ISDIR(hstat.st_mode)) {
            goto bdir_done;
        }
        /* otherwise recursively create it */
        char *sl = std::strchr(bptr, '/');
        while (sl) {
            *sl = '\0';
            if (fstatat(hfd, bptr, &hstat, 0) || !S_ISDIR(hstat.st_mode)) {
                if (mkdirat(hfd, bptr, 0755)) {
                    *sl = '/';
                    goto bdir_done;
                }
            }
            *sl = '/';
            sl = strchr(sl + 1, '/');
        }
        /* actually create the dir itself */
        mkdirat(hfd, bptr, 0755);
    }
bdir_done:
    close(hfd);
    /* build up env and args list */
    std::vector<char> execs{};
    std::size_t argc = 0, nexec = 0;
    auto add_str = [&execs, &nexec](auto &&...s) {
        (execs.insert(execs.end(), s, s + std::strlen(s)), ...);
        execs.push_back('\0');
        ++nexec;
    };
    /* argv starts here */
    add_str("dinit");
    add_str("--user");
    add_str("--ready-fd");
    add_str(pipenum);
    add_str("--services-dir");
    add_str(RUN_PATH, "/", SOCK_DIR, "/", sess.uids, "/", tdirn);
    /* onwards */
    for (auto &sp: cdata->srv_paths) {
        add_str("--services-dir");
        if (sp.data()[0] != '/') {
            add_str(sess.homedir, "/", sp.data());
        } else {
            add_str(sp.data());
        }
    }
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
        add_str("USER=", pw->pw_name);
    }
    if (!have_env_logname) {
        add_str("LOGNAME=", pw->pw_name);
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
    auto *argv = const_cast<char **>(&argp[0]);
    /* try change directory to home, but do not fail */
    chdir(sess.homedir);
    /* finish pam before execing */
    dpam_finalize(pamh);
    /* fire */
    execvpe(argv[0], argv, argv + argc + 1);
}

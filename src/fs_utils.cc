#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "dinit-userservd.hh"

int dir_make_at(int dfd, char const *dname, mode_t mode) {
    int sdfd = openat(dfd, dname, O_RDONLY);
    struct stat st;
    if (fstat(sdfd, &st) || !S_ISDIR(st.st_mode)) {
        close(sdfd);
        if (mkdirat(dfd, dname, mode)) {
            return -1;
        }
        sdfd = openat(dfd, dname, O_RDONLY);
        if (fstat(sdfd, &st)) {
            return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            return -1;
        }
    } else {
        if (fchmod(sdfd, mode)) {
            return -1;
        }
        if (!dir_clear_contents(sdfd)) {
            errno = ENOTEMPTY;
            return -1;
        }
    }
    return sdfd;
}

bool rundir_make(char *rundir, unsigned int uid, unsigned int gid) {
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
                print_err(
                    "rundir: mkdir failed for path (%s)", strerror(errno)
                );
                return false;
            }
        }
        *sl = '/';
        sl = strchr(sl + 1, '/');
    }
    /* create rundir with correct permissions */
    if (mkdir(rundir, 0700)) {
        print_err("rundir: mkdir failed for rundir (%s)", strerror(errno));
        return false;
    }
    if (chown(rundir, uid, gid) < 0) {
        print_err("rundir: chown failed for rundir (%s)", strerror(errno));
        rmdir(rundir);
        return false;
    }
    return true;
}

void rundir_clear(char *rundir) {
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
    if (dir_clear_contents(dfd)) {
        /* was empty */
        rmdir(rundir);
    } else {
        print_dbg("rundir: failed to clear contents of %s", rundir);
    }
}

bool dir_clear_contents(int dfd) {
    if (dfd < 0) {
        /* silently return if an invalid file descriptor */
        return false;
    }
    DIR *d = fdopendir(dfd);
    if (!d) {
        print_err("dir_clear: fdopendir failed (%s)", strerror(errno));
        close(dfd);
        return false;
    }

    unsigned char buf[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    unsigned char *bufp = buf;

    struct dirent *dentb = nullptr, *dent = nullptr;
    std::memcpy(&dentb, &bufp, sizeof(dent));

    for (;;) {
        if (readdir_r(d, dentb, &dent) < 0) {
            print_err("dir_clear: readdir_r failed (%s)", strerror(errno));
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

        print_dbg("dir_clear: clear %s at %d", dent->d_name, dfd);
        int efd = openat(dfd, dent->d_name, O_RDONLY);
        int ufl = 0;

        if (efd < 0) {
            /* this may fail e.g. for invalid sockets, we don't care */
            goto do_unlink;
        }

        struct stat st;
        if (fstat(efd, &st) < 0) {
            print_err("dir_clear: fstat failed (%s)", strerror(errno));
            closedir(d);
            return false;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!dir_clear_contents(efd)) {
                closedir(d);
                return false;
            }
            ufl = AT_REMOVEDIR;
        } else {
            close(efd);
        }

do_unlink:
        if (unlinkat(dfd, dent->d_name, ufl) < 0) {
            print_err("dir_clear: unlinkat failed (%s)", strerror(errno));
            closedir(d);
            return false;
        }
    }

    closedir(d);
    return true;
}

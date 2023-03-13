#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <climits>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "turnstiled.hh"

int dir_make_at(int dfd, char const *dname, mode_t mode) {
    int sdfd = openat(dfd, dname, O_RDONLY | O_NOFOLLOW);
    struct stat st;
    if (fstat(sdfd, &st) || !S_ISDIR(st.st_mode)) {
        close(sdfd);
        if (mkdirat(dfd, dname, mode)) {
            return -1;
        }
        sdfd = openat(dfd, dname, O_RDONLY | O_NOFOLLOW);
        if (sdfd < 0) {
            return -1;
        }
        if (fstat(sdfd, &st) < 0) {
            close(sdfd);
            return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
            close(sdfd);
            errno = ENOTDIR;
            return -1;
        }
    } else {
        if (fchmod(sdfd, mode) < 0) {
            close(sdfd);
            return -1;
        }
        /* dir_clear_contents closes the descriptor, we need to keep it */
        int nfd = dup(sdfd);
        if (nfd < 0) {
            close(sdfd);
            return -1;
        }
        if (!dir_clear_contents(nfd)) {
            close(sdfd);
            errno = ENOTEMPTY;
            return -1;
        }
    }
    return sdfd;
}

bool rundir_make(char *rundir, unsigned int uid, unsigned int gid) {
    struct stat dstat;
    int bfd = open("/", O_RDONLY | O_NOFOLLOW);
    if (bfd < 0) {
        print_err("rundir: failed to open root (%s)", strerror(errno));
        return false;
    }
    char *dirbase = rundir + 1;
    char *sl = std::strchr(dirbase, '/');
    print_dbg("rundir: make directory %s", rundir);
    /* recursively create all parent paths */
    while (sl) {
        *sl = '\0';
        print_dbg("rundir: try make parent %s", rundir);
        int cfd = openat(bfd, dirbase, O_RDONLY | O_NOFOLLOW);
        if (cfd < 0) {
            if (mkdirat(bfd, dirbase, 0755) == 0) {
                cfd = openat(bfd, dirbase, O_RDONLY | O_NOFOLLOW);
            }
        }
        if (cfd < 0 || fstat(cfd, &dstat) < 0) {
            print_err(
                "rundir: failed to make parent %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            close(cfd);
            return false;
        }
        if (!S_ISDIR(dstat.st_mode)) {
            print_err("rundir: non-directory encountered at %s", rundir);
            close(bfd);
            close(cfd);
            return false;
        }
        close(bfd);
        bfd = cfd;
        *sl = '/';
        dirbase = sl + 1;
        sl = std::strchr(dirbase, '/');
    }
    /* now create rundir or at least sanitize its perms */
    if (
        (fstatat(bfd, dirbase, &dstat, AT_SYMLINK_NOFOLLOW) < 0) ||
        !S_ISDIR(dstat.st_mode)
    ) {
        if (mkdirat(bfd, dirbase, 0700) < 0) {
            print_err(
                "rundir: failed to make rundir %s (%s)",
                rundir, strerror(errno)
            );
            close(bfd);
            return false;
        }
    } else if (fchmodat(bfd, dirbase, 0700, AT_SYMLINK_NOFOLLOW) < 0) {
        print_err("rundir: fchmodat failed for rundir (%s)", strerror(errno));
        close(bfd);
        return false;
    }
    if (fchownat(bfd, dirbase, uid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
        print_err("rundir: fchownat failed for rundir (%s)", strerror(errno));
        close(bfd);
        return false;
    }
    close(bfd);
    return true;
}

void rundir_clear(char *rundir) {
    struct stat dstat;
    print_dbg("rundir: clear directory %s", rundir);
    int dfd = open(rundir, O_RDONLY | O_NOFOLLOW);
    /* non-existent */
    if (dfd < 0) {
        return;
    }
    /* an error? */
    if (fstat(dfd, &dstat)) {
        print_dbg("rundir: could not stat %s (%s)", rundir, strerror(errno));
        close(dfd);
        return;
    }
    /* not a directory */
    if (!S_ISDIR(dstat.st_mode)) {
        print_dbg("rundir: %s is not a directory", rundir);
        close(dfd);
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
        int efd = openat(dfd, dent->d_name, O_RDONLY | O_NOFOLLOW);
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

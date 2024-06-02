/* shared non-portable utilities
 *
 * Copyright 2022 q66 <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/un.h>
#if defined(__sun) || defined(sun)
# if __has_include(<ucred.h>)
#  include <ucred.h>
# else
#  include <sys/ucred.h>
# endif
#endif

#include "utils.hh"

bool get_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid) {
#if defined(SO_PEERCRED)
    /* Linux or OpenBSD */
#ifdef __OpenBSD
    struct sockpeercred cr;
#else
    struct ucred cr;
#endif
    socklen_t crl = sizeof(cr);
    if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crl) && (crl == sizeof(cr))) {
        if (uid) {
            *uid = cr.uid;
        }
        if (gid) {
            *gid = cr.gid;
        }
        if (pid) {
            *pid = cr.pid;
        }
        return true;
    }
#elif defined(LOCAL_PEERCRED)
    /* FreeBSD */
    struct xucred cr;
    socklen_t crl = sizeof(cr);
    if (
        !getsockopt(fd, 0, LOCAL_PEERCRED, &cr, &crl) && (crl == sizeof(cr)) &&
        (cr.cr_version == XUCRED_VERSION)
    ) {
        if (uid) {
            *uid = cr.cr_uid;
        }
        if (gid) {
            *gid = cr.cr_gid;
        }
        if (pid) {
            *pid = cr.cr_pid;
        }
        return true;
    }
#elif defined(LOCAL_PEEREID)
    /* NetBSD */
    struct unpcbid cr;
    socklen_t crl = sizeof(cr);
    if (!getsockopt(fd, 0, LOCAL_PEEREID, &cr, &crl) && (crl == sizeof(cr))) {
        if (uid) {
            *uid = cr.unp_euid;
        }
        if (gid) {
            *gid = cr.unp_egid;
        }
        if (pid) {
            *pid = cr.unp_pid;
        }
        return true;
    }
#elif defined(__sun) || defined(sun)
    /* Solaris */
    ucred_t *cr = nullptr;
    if (getpeerucred(fd, &cr) < 0) {
        return false;
    }
    auto uidv = ucred_geteuid(cr);
    auto gidv = ucred_getegid(cr);
    auto pidv = ucred_getpid(cr);
    ucred_free(cr);
    if (
        (uid && (uidv == uid_t(-1))) ||
        (gid && (gidv == gid_t(-1))) ||
        (pid && (pidv < 0))
    ) {
        return false;
    }
    if (uid) {
        *uid = uidv;
    }
    if (gid) {
        *gid = gidv;
    }
    if (pid) {
        *pid = pidv;
    }
    return true;
#else
#error Please implement credentials checking for your OS.
#endif
    return false;
}

unsigned long get_pid_vtnr(pid_t pid) {
    unsigned long vtnr = 0;

#ifdef __linux__
    char buf[256];
    char tbuf[256];
    unsigned long cterm;
    std::snprintf(
        buf, sizeof(buf), "/proc/%lu/stat", static_cast<unsigned long>(pid)
    );
    FILE *f = std::fopen(buf, "rb");
    if (!f) {
        return 0;
    }
    if (!std::fgets(tbuf, sizeof(tbuf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    char *sp = std::strchr(tbuf, ')');
    if (!sp) {
        return 0;
    }
    if (std::sscanf(sp + 2, "%*c %*d %*d %*d %lu", &cterm) != 1) {
        return 0;
    }
    if ((major(cterm) == 0) && (minor(cterm) == 0)) {
        return 0;
    }
    std::snprintf(
        buf, sizeof(buf), "/sys/dev/char/%d:%d", major(cterm), minor(cterm)
    );
    std::memset(tbuf, '\0', sizeof(tbuf));
    if (readlink(buf, tbuf, sizeof(tbuf) - 1) < 0) {
        return 0;
    }
    sp = strrchr(tbuf, '/');
    if (sp && !std::strncmp(sp + 1, "tty", 3)) {
        char *endp = nullptr;
        vtnr = std::strtoul(sp + 4, &endp, 10);
        if (endp && *endp) {
            vtnr = 0;
        }
    }
#else
#error Please add your implementation here
#endif

    return vtnr;
}

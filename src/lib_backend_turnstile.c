#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

// actually a C header too
#include "protocol.hh"

#include "lib_api.h"

typedef struct turnstile_ts {
    int p_fd;
} turnstile_ts;

static int ts_connect(void) {
    struct sockaddr_un saddr;

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.sun_family = AF_UNIX;
    memcpy(saddr.sun_path, DAEMON_SOCK, sizeof(DAEMON_SOCK));

    if (connect(sock, (struct sockaddr const *)&saddr, sizeof(saddr)) < 0) {
        return -1;
    }

    return sock;
}

static bool nts_connect(turnstile_ts *ts) {
    return ((ts->p_fd = ts_connect()) >= 0);
}

static bool backend_ts_active(void) {
    int sock = ts_connect();
    if (sock < 0) {
        return false;
    }
    close(sock);
    return true;
}

static void backend_ts_destroy(turnstile *ts) {
    turnstile_ts *nts = (turnstile_ts *)ts;
    if (nts->p_fd >= 0) {
        close(nts->p_fd);
    }
    free(ts);
}

static turnstile *backend_ts_create(void) {
    turnstile_ts *ret = malloc(sizeof(turnstile_ts));
    if (!ret) {
        return NULL;
    }
    ret->p_fd = -1;

    if (!nts_connect(ret)) {
        int serrno = errno;
        backend_ts_destroy((turnstile *)ret);
        errno = serrno;
        return NULL;
    }

    return (turnstile *)ret;
}

static int backend_ts_get_fd(turnstile *ts) {
    return ((turnstile_ts *)ts)->p_fd;
}

static int backend_ts_dispatch(turnstile *ts, int timeout) {
    (void)ts;
    (void)timeout;
    return 0;
}

static int backend_ts_watch_events(
    turnstile *ts, turnstile_event_callback cb, void *data
) {
    (void)ts;
    (void)cb;
    (void)data;
    return 0;
}

struct backend_api backend_api_turnstile = {
    .active = backend_ts_active,
    .create = backend_ts_create,
    .destroy = backend_ts_destroy,

    .get_fd = backend_ts_get_fd,
    .dispatch = backend_ts_dispatch,
    .watch_events = backend_ts_watch_events,
};

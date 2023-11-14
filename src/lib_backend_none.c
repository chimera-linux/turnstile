#include <stdlib.h>

#include "lib_api.h"

typedef struct turnstile_none {
    int p;
} turnstile_none;

static bool backend_none_active(void) {
    return true;
}

static turnstile *backend_none_create(void) {
    turnstile_none *ret = malloc(sizeof(turnstile_none));
    return (turnstile *)ret;
}

static void backend_none_destroy(turnstile *ts) {
    free(ts);
}

static int backend_none_get_fd(turnstile *ts) {
    (void)ts;
    return -1;
}

static int backend_none_dispatch(turnstile *ts, int timeout) {
    (void)ts;
    (void)timeout;
    return 0;
}

static int backend_none_watch_events(
    turnstile *ts, turnstile_event_callback cb, void *data
) {
    (void)ts;
    (void)cb;
    (void)data;
    return 0;
}

struct backend_api backend_api_none = {
    .active = backend_none_active,
    .create = backend_none_create,
    .destroy = backend_none_destroy,

    .get_fd = backend_none_get_fd,
    .dispatch = backend_none_dispatch,
    .watch_events = backend_none_watch_events,
};

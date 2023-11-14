#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <turnstile.h>

#include "lib_api.h"

extern struct backend_api backend_api_turnstile;
extern struct backend_api backend_api_none;

/* the "current" backend is chosen once per client */
static struct backend_api *backend_api_current;

/* THE API STUBS */

TURNSTILE_API void turnstile_init(void) {
    if (backend_api_current) {
        return;
    }
    if (backend_api_turnstile.active()) {
        backend_api_current = &backend_api_turnstile;
        return;
    }
    backend_api_current = &backend_api_none;
}

TURNSTILE_API turnstile *turnstile_new(void) {
    turnstile_init();
    return backend_api_current->create();
}

TURNSTILE_API void turnstile_free(turnstile *ts) {
    backend_api_current->destroy(ts);
}

TURNSTILE_API int turnstile_get_fd(turnstile *ts) {
    return backend_api_current->get_fd(ts);
}

TURNSTILE_API int turnstile_dispatch(turnstile *ts, int timeout) {
    return backend_api_current->dispatch(ts, timeout);
}

TURNSTILE_API int turnstile_watch_events(
    turnstile *ts, turnstile_event_callback cb, void *data
) {
    return backend_api_current->watch_events(ts, cb, data);
}

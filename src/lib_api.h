#ifndef LIB_API_HH
#define LIB_API_HH

#include <turnstile.h>

#include <stdbool.h>

struct backend_api {
    bool (*active)(void);
    turnstile *(*create)(void);
    void (*destroy)(turnstile *ts);

    int (*get_fd)(turnstile *ts);
    int (*dispatch)(turnstile *ts, int timeout);
    int (*watch_events)(turnstile *ts, turnstile_event_callback cb, void *data);
};

#endif

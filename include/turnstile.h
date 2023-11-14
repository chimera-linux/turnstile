/* @file turnstile.h
 *
 * @brief The libturnstile public API
 *
 * This is the public API of libturnstile, an abstraction library for
 * session tracking.
 *
 * The API is not safe to access from multiple threads. Use a lock if
 * you wish to do so. Using multiple turnstiles within a process is
 * permitted, and they can be used independently without a lock. Using
 * global APIs without a turnstile object does not require locking.
 *
 * @copyright See the attached COPYING.md for more information.
 */

#ifndef TURNSTILE_H
#define TURNSTILE_H

#if defined(__GNUC__) && (__GNUC__ >= 4)
#  define TURNSTILE_API __attribute__((visibility("default")))
#else
#  define TURNSTILE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The turnstile.
 *
 * The turnstile is a handle hich contains all the client-local session
 * tracking state. Some APIs require a connected turnstile, while some
 * allow dual operation (passing NULL is allowed).
 *
 * APIs in connection mode need an event/dispatch loop and receive data
 * from a connected peer. Global APIs, on the other hand, rely on publicly
 * available out-of-process data, and thus do not require any further state,
 * connection, or a loop.
 */
typedef struct turnstile turnstile;

typedef enum turnstile_event {
    TURNSTILE_EVENT_LOGIN_NEW = 1,
    TURNSTILE_EVENT_LOGIN_REMOVED,
    TURNSTILE_EVENT_LOGIN_CHANGED,
    TURNSTILE_EVENT_SESSION_NEW,
    TURNSTILE_EVENT_SESSION_REMOVED,
    TURNSTILE_EVENT_SESSION_CHANGED,
} turnstile_event;

/** @brief The turnstile event callback.
 *
 * A callback may be registered with turnstile_watch_events().
 * The turnstile is passed, along with the event type, the id of the
 * affected object, and custom data provided during callback registration.
 *
 * For forward-compatible use, you should always filter for the specific
 * event type you require.
 */
typedef void (*turnstile_event_callback)(turnstile *ts, int event, unsigned long id, void *data);

/** @brief Initialize a turnstile backend.
 *
 * Calling this will result in a backend being chosen for the lifetime of
 * the program. The available backends depend on what is compiled into the
 * library, and follow a priority order, with a fallback null backend being
 * always last.
 *
 * Calling this API with an already chosen backend does nothing.
 */
TURNSTILE_API void turnstile_init(void);

/** @brief Create a new turnstile.
 *
 * Creating a new turnstile will connect to a backend. If no backend has
 * been chosen yet (via turnstile_init()), it will be chosen now. Note that
 * to actually use other APIs, a backend needs to be chosen, and they will
 * not choose it for you.
 *
 * Afterwards, you will want to either integrate it with your event loop
 * by getting a file descriptor with turnstile_get_fd(), polling it and
 * dispatching with turnstile_dispatch(), or if you don't have an event
 * loop, you can create your own dispatch loop (and don't need to poll).
 *
 * @return A turnstile, or NULL on error (errno set).
 */
TURNSTILE_API turnstile *turnstile_new(void);

/** @brief Release the given turnstile.
 *
 * This will free the client-local state. Connection will be closed.
 *
 * @param ts The turnstile.
 * @return Zero on success, a negative value on error (errno set).
 */
TURNSTILE_API void turnstile_free(turnstile *ts);

/** @brief Get a pollable file descriptor for the given turnstile.
 *
 * This can be used for integration into event loops. You should poll the
 * resulting file descriptor in your event loop and call turnstile_dispatch()
 * upon availability of data.
 *
 * The client does not own the file descriptor, so it does not need to close
 * it manually.
 *
 * @param ts The turnstile.
 * @return A pollable fd, or a negative value on error (errno set).
 */
TURNSTILE_API int turnstile_get_fd(turnstile *ts);

/** @brief Dispatch the given turnstile.
 *
 * Upon reception of data (availability known through turnstile_get_fd()
 * descriptor), process the data. Registered callbacks and other things
 * will be triggered during the process.
 *
 * The timeout specifies how long to wait for data. Specifying the value of 0
 * means that no timeout will be given, -1 means potentially infinite timeout,
 * and a positive value is in milliseconds. Synchronous systems may want a
 * potentially infinite timeout (and no blocking) while async systems will
 * want to dispatch only what they have to avoid main loop stalls.
 *
 * @param ts The turnstile.
 * @param timeout The timeout.
 * @return A number of messages processed, or a negative value (errno set).
 */
TURNSTILE_API int turnstile_dispatch(turnstile *ts, int timeout);

/** @brief Add a callback to watch for turnstile events.
 *
 * Upon an event (received through turnstile_dispatch()), the given callback
 * will be called. Events may include new logins, sessions, session state
 * changes, session drops, and so on. The details can be filtered by checking
 * the callback parameters. You can pass custom data with the extra parameter.
 *
 * @param ts The turnstile.
 * @param data Extra data to always pass to the callback.
 * @return Zero on success, a negative value on error (errno set).
 */
TURNSTILE_API int turnstile_watch_events(turnstile *ts, turnstile_event_callback cb, void *data);

#ifdef __cplusplus
}
#endif

#endif

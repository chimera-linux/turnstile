#include <cctype>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <utility>

#include "turnstiled.hh"

static void read_bool(char const *name, char const *value, bool &val) {
    if (!std::strcmp(value, "yes")) {
        val = true;
    } else if (!std::strcmp(value, "no")) {
        val = false;
    } else {
        syslog(
            LOG_WARNING,
            "Invalid configuration value '%s' for '%s' (expected yes/no)",
            value, name
        );
    }
}

void cfg_read(char const *cfgpath) {
    char buf[DIRLEN_MAX];

    auto *f = std::fopen(cfgpath, "r");
    if (!f) {
        syslog(
            LOG_NOTICE, "No configuration file '%s', using defaults", cfgpath
        );
        return;
    }

    while (std::fgets(buf, DIRLEN_MAX, f)) {
        auto slen = strlen(buf);
        /* ditch the rest of the line if needed */
        if ((buf[slen - 1] != '\n')) {
            while (!std::feof(f)) {
                auto c = std::fgetc(f);
                if (c == '\n') {
                    std::fgetc(f);
                    break;
                }
            }
        }
        char *bufp = buf;
        /* drop trailing whitespace */
        while (std::isspace(bufp[slen - 1])) {
            bufp[--slen] = '\0';
        }
        /* drop leading whitespace */
        while (std::isspace(*bufp)) {
            ++bufp;
        }
        /* comment or empty line */
        if (!*bufp || (*bufp == '#')) {
            continue;
        }
        /* find the assignment */
        char *ass = strchr(bufp, '=');
        /* invalid */
        if (!ass || (ass == bufp)) {
            syslog(LOG_WARNING, "Malformed configuration line: %s", bufp);
            continue;
        }
        *ass = '\0';
        /* find the name */
        char *preass = (ass - 1);
        while (std::isspace(*preass)) {
            *preass-- = '\0';
        }
        /* empty name */
        if (preass == bufp) {
            syslog(LOG_WARNING, "Invalid configuration line name: %s", bufp);
            continue;
        }
        /* find the value */
        while (std::isspace(*++ass)) {
            continue;
        }
        /* supported config lines */
        if (!std::strcmp(bufp, "debug")) {
            read_bool("debug", ass, cdata->debug);
        } else if (!std::strcmp(bufp, "debug_stderr")) {
            read_bool("debug_stderr", ass, cdata->debug_stderr);
        } else if (!std::strcmp(bufp, "manage_rundir")) {
            read_bool("manage_rundir", ass, cdata->manage_rdir);
        } else if (!std::strcmp(bufp, "export_dbus_address")) {
            read_bool("export_dbus_address", ass, cdata->export_dbus);
        } else if (!std::strcmp(bufp, "linger")) {
            if (!std::strcmp(ass, "maybe")) {
                cdata->linger = false;
                cdata->linger_never = false;
            } else {
                read_bool("linger", ass, cdata->linger);
                cdata->linger_never = !cdata->linger;
            }
        } else if (!std::strcmp(bufp, "backend")) {
            if (!std::strcmp(ass, "none")) {
                cdata->backend.clear();
                cdata->disable = true;
            } else if (!std::strlen(ass)) {
                syslog(
                    LOG_WARNING,
                    "Invalid config value for '%s' (must be non-empty)", bufp
                );
            } else {
                cdata->backend = ass;
            }
        } else if (!std::strcmp(bufp, "rundir_path")) {
            std::string rp = ass;
            if (!rp.empty() && ((rp.back() == '/') || (rp.front() != '/'))) {
                syslog(
                    LOG_WARNING,
                    "Invalid config value for '%s' (%s)", bufp, rp.data()
                );
            } else {
                cdata->rdir_path = std::move(rp);
            }
        } else if (!std::strcmp(bufp, "login_timeout")) {
            char *endp = nullptr;
            auto tout = std::strtoul(ass, &endp, 10);
            if (*endp || (endp == ass)) {
                syslog(
                    LOG_WARNING,
                    "Invalid config value '%s' for '%s' (expected integer)",
                    ass, bufp
                );
            } else {
                cdata->login_timeout = time_t(tout);
            }
        }
    }
}

bool cfg_expand_rundir(
    char *dest, std::size_t destsize, char const *tmpl,
    unsigned int uid, unsigned int gid
) {
    auto destleft = destsize;
    while (*tmpl) {
        auto mark = std::strchr(tmpl, '%');
        if (!mark) {
            /* no formatting mark in the rest of the string, copy all */
            auto rlen = std::strlen(tmpl);
            if (destleft > rlen) {
                /* enough space incl terminating zero */
                std::memcpy(dest, tmpl, rlen + 1);
                return true;
            } else {
                /* not enough space left */
                return false;
            }
        }
        /* copy up to mark */
        auto rlen = std::size_t(mark - tmpl);
        if (rlen) {
            if (destleft > rlen) {
                std::memcpy(dest, tmpl, rlen);
                destleft -= rlen;
                dest += rlen;
            } else {
                /* not enough space left */
                return false;
            }
        }
        /* trailing % or %%, just copy it as is */
        if (!mark[1] || ((mark[1] == '%') && !mark[2])) {
            if (destleft > 1) {
                *dest++ = '%';
                *dest++ = '\0';
                return true;
            }
            return false;
        }
        ++mark;
        unsigned int wid;
        switch (mark[0]) {
            case 'u':
                wid = uid;
                goto writenum;
            case 'g':
                wid = gid;
writenum:
                if (destleft <= 1) {
                    /* not enough space */
                    return false;
                } else {
                    auto nw = std::snprintf(dest, destleft, "%u", wid);
                    if ((nw < 0) || (std::size_t(nw) >= destleft)) {
                        return false;
                    }
                    dest += nw;
                    destleft -= nw;
                    tmpl = mark + 1;
                    continue;
                }
            case '%':
                if (destleft > 1) {
                    destleft -= 1;
                    *dest++ = *mark++;
                    tmpl = mark;
                    continue;
                } else {
                    return false;
                }
            default:
                /* copy as is */
                if (destleft > 2) {
                    destleft -= 2;
                    *dest++ = '%';
                    *dest++ = *mark++;
                    tmpl = mark;
                    continue;
                } else {
                    return false;
                }
        }
    }
    *dest = '\0';
    return true;
}

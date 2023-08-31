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
    char buf[1024];

    auto *f = std::fopen(cfgpath, "r");
    if (!f) {
        syslog(
            LOG_NOTICE, "No configuration file '%s', using defaults", cfgpath
        );
        return;
    }

    while (std::fgets(buf, sizeof(buf), f)) {
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
        } else if (!std::strcmp(bufp, "root_session")) {
            read_bool("root_session", ass, cdata->root_session);
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

void cfg_expand_rundir(
    std::string &dest, char const *tmpl, unsigned int uid, unsigned int gid
) {
    char buf[32];
    while (*tmpl) {
        auto mark = std::strchr(tmpl, '%');
        if (!mark) {
            /* no formatting mark in the rest of the string, copy all */
            dest += tmpl;
            break;
        }
        /* copy up to mark */
        auto rlen = std::size_t(mark - tmpl);
        if (rlen) {
            dest.append(tmpl, rlen);
        }
        /* trailing % or %%, just copy it as is */
        if (!mark[1] || ((mark[1] == '%') && !mark[2])) {
            dest.push_back('%');
            break;
        }
        ++mark;
        unsigned int wid;
        switch (*mark) {
            case 'u':
                wid = uid;
                goto writenum;
            case 'g':
                wid = gid;
writenum:
                std::snprintf(buf, sizeof(buf), "%u", wid);
                dest += buf;
                break;
            case '%':
                dest.push_back(*mark);
                break;
            default:
                dest.push_back('%');
                dest.push_back(*mark);
                break;
        }
        tmpl = mark + 1;
    }
}

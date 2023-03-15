# turnstile

Turnstile is a work in progress effort to create a session/login tracker to
serve as a fully featured alternative to the logind subproject from systemd,
and to provide a neutral API to both our session tracker and to logind itself.

It is:

* a session/login tracker
* a service-manager-agnostic way to manage per-user service managers
  for user services

it is not:

* a seat tracker (you want [seatd](https://git.sr.ht/~kennylevinsen/seatd) for
  that)

it is not yet:

* a library to examine session information

## History

Its original name was dinit-userservd and it was created as a way to auto-spawn
user instances of [Dinit](https://github.com/davmac314/dinit) upon login and
shut them down upon logout, to allow for clean management of user services.

Soon after it outgrew its original responsibilities and gained adjacent
functionality such as handling of `XDG_RUNTIME_DIR`. At that point, it was
decided that it would be worthwhile to expand the overall scope, as most of
the effort was already there.

## Purpose

Its ultimate goal is to provide a fully featured replacement for the `logind`
component of systemd, solving the current status quo where `logind` is the
de-facto standard, but at the same time very much tied to systemd.

While there are workarounds such as elogind, these are far from ideal. For
instance, elogind is just a stubbed out version of upstream logind, and
only provides the bare minimum, so systems using it are left without support
for user services and other useful functionality.

This goal has not yet been accomplished, as at the moment Turnstile is only
a daemon and does not provide any API. This will change in the future. This
API will provide a way to access the session information, but will not deal
with seat management. You will be able to use the library together with
`libseat` without conflicting. The API will expose the bare minimum needed
for the two libraries to interoperate.

Turnstile is designed to not care about what service manager it is used with.
None of the daemon code cares, instead leaving this to separate backends.

## Backends

Turnstile is capable of supporting multiple service managers, and the code
makes no assumptions about what service manager one is using to handle user
instances.

That said, right now the only available backend is for Dinit, which also
serves as an example for implementation of other backends. There is also
the built-in `none` backend, which does not handle user services at all
and lets the daemon do only session tracking and auxiliary tasks. The
used backend is configured in `turnstiled.conf`.

A backend is a very trivial shell script. Its responsibility is to launch
the service manager and ensure that the daemon is notified of its readiness,
which is handled with a special file descriptor.

## How it works

There are three parts.

1) The daemon, `turnstiled`.
2) The PAM module, `pam_turnstile.so`.
3) The chosen backend.

The daemon needs to be running in some way. Usually you will spawn it as a
system-wide service. It needs to be running as the superuser. The daemon is
what keeps track of the session state, and what launches the user service
manager through the backend.

The PAM module needs to be in your login path. This will differ per-distro,
but typically it will involve a line like this:

```
session optional pam_turnstile.so
```

When the daemon starts, it opens a Unix domain socket. This is where it listens
for connections. When a user tries to log in, the PAM module will open one such
connection and communicate the information to the daemon using a custom internal
protocol.

Once the handshake is done and all the state is properly negotiated, the daemon
will try to spawn the service manager for the user. It does so through the
backend, which is tasked with the `run` action.

The backend is invoked as a shell script, specifically as a login shell. This
means that it starts with a clean environment, but has many of the common
env vars (such as `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH` and others)
freshly initialized, and the shell profile is also sourced. Additionally,
it sets up a PAM session (but without authentication) in order to allow the
service manager's environment to have default resource limits and other
session matters equivalent to a real login.

After performing some initial preparation (which is backend-specific), the
backend will simply replace itself with the desired service manager. There
is a special file descriptor that is passed to the backend. The service
manager (or possibly even the backend itself) can write a string of data
in there when it's ready enough to accept outside commands.

Once that has happened, the daemon will invoke the backend once more, this
time with the `ready` action and as a regular (non-login) shell script, without
any special environment setup. It passes the previously received string as
an argument. The backend then has the responsibility to wait as long as it
takes (or until a timeout is reached) for the initial user services to start
up.

Afterwards, the daemon will send a message back to the PAM module, allowing
the login to proceed. This ensures that by the time the user gets their login
terminal, the autostarted user services are already up.

When the user logs out (or rather, when the last login of the user has logged
out), this service manager will shut down by default. However, it can also be
configured to linger.

### Auxiliary tasks

The daemon can also perform various adjacent tasks. As it can be configured
through `turnstiled.conf`, many of these can be enabled or disabled as needed.

#### Rundir management

The environment variable `XDG_RUNTIME_DIR` is by default set in the user's
login environment. Typically it is something like `/run/user/$UID`.

Turnstile can also create this directory. Whether it creates it by default
comes down to how the build is configured. Environments using stock `logind`
will want to keep it off in order to avoid conflicting, while others may
want to turn it on.

Regardless of the default behavior, it can be altered in the configuration file.

#### Session persistence

It is possible to configure the sessions to linger, so the user services will
remain up even after logout. This can be done either per-user, or globally.

Note that session peristence relies on rundir creation being enabled, as in
the other case the daemon cannot know whether the other management solution
is not deleting the rundir, and many user services rely on its existence.
This can be manually overridden with an environment variable, at your own
risk.

#### D-Bus session bus address

By default, the address of the D-Bus session bus will be exported into the
login environment and set to something like `unix:path=$XDG_RUNTIME_DIR/bus`,
if that socket exists and is valid in that path.

This allows the D-Bus session bus to be managed as a user service, to get
systemd-style behavior with a single session bus shared between user logins.
It can be explicitly disabled if necessary, but mostly there is no need to
as the variable will not be exported if the bus does not exist there.

Note that this does not mean the bus address is exported into the activation
environment, as turnstile does not know about it. The user service that spawns
the session bus needs to take care of that, e.g. with `dinitctl setenv` for
Dinit. Only this way will other user services know about the session bus.

## Setup

Build and install the project. It uses [Meson](https://mesonbuild.com/) and
follows the standard Meson workflow. Example:

```
$ mkdir build && cd build
$ meson .. --prefix=/usr
$ ninja all
$ sudo ninja install
```

The dependencies are:

1) A POSIX-compliant OS (Chimera Linux is the reference platform)
2) A C++17 compiler
3) Meson and Ninja (to build)
5) PAM

The Dinit backend requires at least Dinit 0.16 or newer, older versions will
not work. The project also installs an example Dinit service for starting
the daemon.

# dinit-userservd

This is a daemon and a PAM module to handle user services management with the
`dinit` init system and service manager (https://github.com/davmac314/dinit).

It was created for the needs of the Chimera Linux project. It is not expected
to work properly anywhere else by default (those use cases are unsupported),
and issues or feature requests specific to other environments will not be
addressed. Patches may be accepted, provided they are not disruptive or
introduce excessive complexity.

## How it works

The project consists of a daemon and a PAM module. The PAM module is enabled
for example by adding this in your login path:

```
session optional pam_dinit_userservd.so
```

The daemon must simply be running in some way. If it is not running, you will
still be able to log in with the above setup, but it will not do anything.

A recommended way to manage the daemon is using a `dinit` service that is
provided with the project.

The daemon opens a control socket. The PAM module will make connections to
it upon session start (and close it upon session end). When the daemon
receives a connection, it will negotiate a session with the PAM module
and upon first login of each user, spawn a user `dinit` instance.

This instance is supervised, if it fails in any way it gets automatically
restarted.

It will register the following service directories:

* `~/.config/dinit.d`
* `/etc/dinit.d/user`
* `/usr/local/lib/dinit.d/user`
* `/usr/lib/dinit.d/user`

You do not need to provide a `boot` service (in fact, you should not).
By default, the following path is used for autostarted user services:

* `~/.config/dinit.d/boot.d`

Simply drop symlinks to whatever services you want in there and they will
get started with your login.

The login proceeds once the `dinit` instance has signaled readiness (which
is once it has started its autostart services). It does so via an internal
notification mechanism.

### Dbus handling

The daemon also supports handling of D-Bus session bus. If the socket
`/run/user/UID/bus` exists by the time readiness has been signaled, the
variable `DBUS_SESSION_BUS_ADDRESS` will automatically be exported into
the login environment.

That way it is possible to manage the session bus as a user service without
having to spawn it on-demand.

For user services that need to be run within the session, the `dinit-run-dbus`
script is provided as a wrapper. Therefore, you can write services like:

```
type = process
command = /usr/bin/dinit-run-dbus your-command arguments
...
```

## TODO

* Do not hardcode things to make it easier to use for other projects.

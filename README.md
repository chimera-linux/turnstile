# dinit-userservd

This is a daemon and a PAM module to handle user services management with the
`dinit` init system and service manager (https://github.com/davmac314/dinit).

It was created chiefly for the needs of the Chimera Linux project and may not
work properly elsewhere. It may depend on bleeding edge Git versions of `dinit`.
Issues or feature requests specific to other environments will not be addressed.
Patches are welcome (provided they are not disruptive or introduce excessive
complexity) and if you believe your particular problem is not specific to your
system, feel free to report it.

**Required `dinit` version:** at least Git `be98fa3d3a87b05bb23ee5c9b9a0ecf3cb165c14`

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
restarted. It runs outside of the login itself, as only one instance must
exist per user (who can have multiple logins) and it only exists once the
last login has logged out. This means that environment variables of the
login do not exist within the user instance by default, and they must be
exported into it through other means.

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

### Configuration file

By default, a configuration file `dinit-userservd.conf` is read from `/etc`.
You can pass your own path on the command line as its first argument.

See the supplied `dinit-userservd.conf` for possible options.

### XDG_RUNTIME_DIR handling

Usually, `XDG_RUNTIME_DIR` is managed by another daemon, typically `elogind`
for Chimera. However, some people may not be running `elogind` or a similar
solution. The daemon is capable of managing the runtime directory for you
if you enable it.

By default, `XDG_RUNTIME_DIR` is exported into the user service environment
regardless of if managed or not.

Both options can be tweaked in the configuration file.

### Dbus handling

The daemon also supports handling of D-Bus session bus. If the socket
`RUNDIR/bus` exists by the time readiness has been signaled, the
variable `DBUS_SESSION_BUS_ADDRESS` will automatically be exported into
the login environment.

That way it is possible to manage the session bus as a user service without
having to spawn it on-demand.

User services making use of the bus need to ensure that the variable is
exported in their launch environment in some way, as the service manager
runs outside of the user's login session. This can be done for example
with `dinitctl setenv`, which you can make a part of your session bus
service startup process.

D-Bus handling can be disabled in the configuration file. It is also
not handled at all if the runtime directory path is not exported.

## TODO

* Do not hardcode things to make it easier to use for other projects.

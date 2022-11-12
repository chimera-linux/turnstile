pam_dinit_userservd(8)

# NAME

pam\_dinit\_userservd - register user sessions in *dinit-userservd*(8)

# SYNOPSIS

pam\_dinit\_userservd.so

# DESCRIPTION

*pam\_dinit\_userservd* registers user sessions with the main daemon,
which allows them to be tracked.

It communicates with the daemon over its control socket. Upon login,
it opens a connection to it, and this connection lasts for as long as
the login lasts.

By keeping track of the connections, the daemon can be aware of the
full lifetime of the session.

The login will only proceed in one of the following cases:

- The daemon has replied with a success.
- The daemon has replied with a failure.
- The connection was closed.

Upon success, the daemon will have already started all user services.
If that is the case, it may also initialize some environment variables:

. _$DBUS\_SESSION\_BUS\_ADDRESS_ is exported assuming 'RUNDIR/bus' exists
  and is a valid socket, where 'RUNDIR' is the runtime directory the
  daemon is potentially managing. The value of the environment variable
  becomes _unix:path=/path/to/bus_.
. _$XDG\_RUNTIME\_DIR_ is exported if the daemon's _manage\_rundir_ is
  enabled in the configuration.

Upon success, the module returns _PAM\_SUCCESS_. In any other case, the
module returns _PAM\_SESSION\_ERR_.

# OPTIONS

The module takes no options.

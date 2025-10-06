turnstiled(8)

# NAME

turnstiled - the main session management daemon

# SYNOPSIS

*turnstiled* [config_path]

# DESCRIPTION

*turnstiled* is a daemon that tracks user sessions and optionally spawns
and manages service managers for them.

For configuration, see *turnstiled.conf*(5).

Upon user login, it spawns an instance of the chosen service manager for the
user, while upon last logout, it shuts down this instance (unless configured
to linger).

User logins and logouts are communicated via *pam\_turnstile*(8).

The daemon itself takes no options other than possibly a configuration
file path as its sole argument. If not provided, the default path is
used, typically _/etc/turnstile/turnstiled.conf_.

# XDG\_RUNTIME\_DIR MANAGEMENT

The daemon can also serve as the manager of the _$XDG\_RUNTIME\_DIR_
environment variable and directory.

# ENVIRONMENT

*TURNSTILED\_LINGER\_ENABLE\_FORCE*
	If set during daemon startup (to any value), enable lingering even if
	rundir management is disabled. This is primarily for people who want
	to use the linger functionality and have worked around the problem in
	their own rundir management system. Enabling this without having worked
	around the problem may lead to unfortunate consequences.

	Of course, lingering still has to be enabled in the configuration.

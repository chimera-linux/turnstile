dinit-userservd(8)

# NAME

dinit-userservd - the main session management daemon

# SYNOPSIS

*dinit-userservd* [config_path]

# DESCRIPTION

*dinit-userservd* is a daemon that manages user instances for the Dinit
service manager.

For configuration, see *dinit-userservd.conf*(5).

Upon user login, it spawns an instance of Dinit for the user, while upon
last logout, it shuts down this instance (unless configured to longer).

User logins and logouts are communicated via *pam\_dinit\_userservd*(8).

The daemon itself takes no options other than possibly a configuration
file path as its sole argument. If not provided, the default path is
used, typically _/etc/dinit-userservd.conf_.

# XDG\_RUNTIME\_DIR MANAGEMENT

The daemon can also serve as the manager of the _$XDG\_RUNTIME\_DIR_
environment variable and directory.

# ENVIRONMENT

*DINIT\_USERSERVD\_LINGER\_ENABLE\_FORCE*
	If set during daemon startup (to any value), enable lingering even if
	rundir management is disabled. This is primarily for people who want
	to use the linger functionality and have worked around the problem in
	their own rundir management system. Enabling this without having worked
	around the problem may lead to unfortunate consequences.

	Of course, lingering still has to be enabled in the configuration.

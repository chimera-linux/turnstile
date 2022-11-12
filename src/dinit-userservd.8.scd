dinit-userservd(8)

# NAME

dinit-userservd - the main session management daemon

# SYNOPSIS

*elogind* [config_path]

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

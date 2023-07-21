/* shared non-portable utilities
 *
 * Copyright 2022 Daniel "q66" Kolesa <q66@chimera-linux.org>
 * License: BSD-2-Clause
 */

#ifndef UTILS_HH
#define UTILS_HH

#include <sys/types.h>

bool get_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid);
unsigned long get_pid_vtnr(pid_t pid);

#endif

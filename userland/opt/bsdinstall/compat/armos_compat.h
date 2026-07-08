#ifndef ARMOS_BSDINSTALL_COMPAT_H
#define ARMOS_BSDINSTALL_COMPAT_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef HAVE_NBTOOL_CONFIG_H
#define HAVE_NBTOOL_CONFIG_H 1
#endif

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(uintptr_t)(const void *)(a))
#endif

#ifndef __arraycount
#define __arraycount(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

#ifndef MAXBSIZE
#define MAXBSIZE 8192
#endif

#ifndef ALLPERMS
#define ALLPERMS 07777
#endif

#ifndef DEFFILEMODE
#define DEFFILEMODE 0666
#endif

#ifndef TARGET_STRIP
#define TARGET_STRIP "/usr/bin/strip"
#endif

#define vfork fork

int armos_install_open(const char *path, int flags, ...);
int armos_install_mkstemp(char *path);
int armos_install_close(int fd);
int armos_install_fchmod(int fd, mode_t mode);
int armos_install_fchown(int fd, uid_t owner, gid_t group);
int asprintf(char **strp, const char *fmt, ...);
int utimes(const char *path, const struct timeval times[2]);

#define open armos_install_open
#define mkstemp armos_install_mkstemp
#define close armos_install_close
#define fchmod armos_install_fchmod
#define fchown armos_install_fchown

#endif /* ARMOS_BSDINSTALL_COMPAT_H */

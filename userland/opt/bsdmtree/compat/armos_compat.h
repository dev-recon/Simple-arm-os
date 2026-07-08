#ifndef ARMOS_BSDMTREE_COMPAT_H
#define ARMOS_BSDMTREE_COMPAT_H

#include <stdint.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef HAVE_NBTOOL_CONFIG_H
#define HAVE_NBTOOL_CONFIG_H 1
#endif

#ifndef HAVE_STRUCT_STAT_ST_FLAGS
#define HAVE_STRUCT_STAT_ST_FLAGS 0
#endif

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef __printflike
#define __printflike(fmtarg, firstvararg) __attribute__((__format__(__printf__, fmtarg, firstvararg)))
#endif

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(uintptr_t)(const void *)(a))
#endif

#ifndef __arraycount
#define __arraycount(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef S_ISTXT
#define S_ISTXT S_ISVTX
#endif

#ifndef ALLPERMS
#define ALLPERMS 07777
#endif

#ifndef major
#define major(dev) (((dev) >> 8) & 0xff)
#endif

#ifndef minor
#define minor(dev) ((dev) & 0xff)
#endif

#ifndef makedev
#define makedev(maj, min) ((((maj) & 0xff) << 8) | ((min) & 0xff))
#endif

#define UF_NODUMP 0x00000001
#define UF_IMMUTABLE 0x00000002
#define UF_APPEND 0x00000004
#define UF_OPAQUE 0x00000008
#define UF_SETTABLE (UF_NODUMP | UF_IMMUTABLE | UF_APPEND | UF_OPAQUE)
#define SF_ARCHIVED 0x00010000
#define SF_IMMUTABLE 0x00020000
#define SF_APPEND 0x00040000
#define SF_SETTABLE (SF_ARCHIVED | SF_IMMUTABLE | SF_APPEND)

#define FPARSELN_UNESCESC 0x01
#define FPARSELN_UNESCCONT 0x02
#define FPARSELN_UNESCCOMM 0x04
#define FPARSELN_UNESCALL (FPARSELN_UNESCESC | FPARSELN_UNESCCONT | FPARSELN_UNESCCOMM)

int asprintf(char **strp, const char *fmt, ...);
char *fparseln(FILE *fp, size_t *len, size_t *lineno, const char delim[3], int flags);
int lchown(const char *path, uid_t owner, gid_t group);
int lchmod(const char *path, mode_t mode);
int lchflags(const char *path, unsigned long flags);
int mkfifo(const char *path, mode_t mode);
int utimes(const char *path, const struct timeval times[2]);
char *getlogin(void);
int gethostname(char *name, size_t len);

#endif /* ARMOS_BSDMTREE_COMPAT_H */

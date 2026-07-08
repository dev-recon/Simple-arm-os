#ifndef ARMOS_BSDPATCH_COMPAT_H
#define ARMOS_BSDPATCH_COMPAT_H

#include <stdarg.h>
#include <stdio.h>
#include <sys/cdefs.h>

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef __printflike
#define __printflike(fmtarg, firstvararg) __attribute__((__format__(__printf__, fmtarg, firstvararg)))
#endif

#ifndef __RCSID
#define __RCSID(x)
#endif

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(unsigned long)(const void *)(a))
#endif

#ifndef _PATH_TMP
#define _PATH_TMP "/tmp"
#endif

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

#ifndef MADV_SEQUENTIAL
#define MADV_SEQUENTIAL 0
#endif

#define getline __getline
#define madvise(addr, len, advice) 0

void setprogname(const char *name);
const char *getprogname(void);
int asprintf(char **ret, const char *fmt, ...);
int vasprintf(char **ret, const char *fmt, va_list ap);

#endif /* ARMOS_BSDPATCH_COMPAT_H */

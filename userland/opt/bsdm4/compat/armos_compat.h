#ifndef ARMOS_BSDM4_COMPAT_H
#define ARMOS_BSDM4_COMPAT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/cdefs.h>

#ifndef HAVE_NBTOOL_CONFIG_H
#define HAVE_NBTOOL_CONFIG_H 1
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

#ifndef _PATH_TMP
#define _PATH_TMP "/tmp"
#endif

void setprogname(const char *name);
const char *getprogname(void);
intmax_t strtoi(const char *nptr, char **endptr, int base, intmax_t lo,
    intmax_t hi, int *rstatus);

#endif /* ARMOS_BSDM4_COMPAT_H */

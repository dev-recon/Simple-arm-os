#ifndef ARMOS_BSDDIFF_COMPAT_H
#define ARMOS_BSDDIFF_COMPAT_H

#include <dirent.h>
#include <limits.h>
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

#ifndef d_fileno
#define d_fileno d_ino
#endif

#ifndef roundup
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#endif

void setprogname(const char *name);
const char *getprogname(void);
char *fgetln(FILE *stream, size_t *lenp);
int reallocarr(void *ptr, size_t nmemb, size_t size);
int asprintf(char **ret, const char *fmt, ...);
int vasprintf(char **ret, const char *fmt, va_list ap);
int scandir(const char *dirname, struct dirent ***namelist,
    int (*selectfn)(const struct dirent *),
    int (*compar)(const struct dirent **, const struct dirent **));
int alphasort(const struct dirent **d1, const struct dirent **d2);

#endif /* ARMOS_BSDDIFF_COMPAT_H */

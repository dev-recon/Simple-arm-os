#ifndef ARMOS_BSDXARGS_COMPAT_H
#define ARMOS_BSDXARGS_COMPAT_H

#include <stdint.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include <unistd.h>

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

#define vfork fork
#define sysconf armos_xargs_sysconf

extern const char *const sys_signame[];

void setprogname(const char *name);
const char *getprogname(void);
char *fgetln(FILE *stream, size_t *lenp);
long armos_xargs_sysconf(int name);

#endif /* ARMOS_BSDXARGS_COMPAT_H */

#include "armos_compat.h"

#undef vfork
#undef sysconf

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *program_name = "xargs";

const char *const sys_signame[] = {
    "ZERO", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "EMT",
    "FPE", "KILL", "BUS", "SEGV", "SYS", "PIPE", "ALRM", "TERM",
    "URG", "STOP", "TSTP", "CONT", "CHLD", "TTIN", "TTOU", "IO",
    "WINCH", "USR1", "USR2", "RTMIN", "RT28", "RT29", "RT30", "RTMAX"
};

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "xargs";
        return;
    }

    slash = strrchr(name, '/');
    program_name = slash != NULL ? slash + 1 : name;
}

const char *
getprogname(void)
{
    return program_name;
}

static void
vwarn_common(int code, const char *fmt, va_list ap)
{
    if (program_name != NULL && *program_name != '\0')
        fprintf(stderr, "%s: ", program_name);

    if (fmt != NULL && *fmt != '\0') {
        vfprintf(stderr, fmt, ap);
        if (code != 0)
            fprintf(stderr, ": ");
    }

    if (code != 0)
        fprintf(stderr, "%s", strerror(code));

    fputc('\n', stderr);
}

void
vwarn(const char *fmt, va_list ap)
{
    vwarn_common(errno, fmt, ap);
}

void
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
}

void
vwarnx(const char *fmt, va_list ap)
{
    vwarn_common(0, fmt, ap);
}

void
warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}

void
verr(int eval, const char *fmt, va_list ap)
{
    vwarn_common(errno, fmt, ap);
    exit(eval);
}

void
err(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verr(eval, fmt, ap);
    va_end(ap);
}

void
verrx(int eval, const char *fmt, va_list ap)
{
    vwarn_common(0, fmt, ap);
    exit(eval);
}

void
errx(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verrx(eval, fmt, ap);
    va_end(ap);
}

char *
fgetln(FILE *stream, size_t *lenp)
{
    static char *line;
    static size_t cap;
    size_t len = 0;
    int ch;

    if (stream == NULL || lenp == NULL) {
        errno = EINVAL;
        return NULL;
    }

    while ((ch = fgetc(stream)) != EOF) {
        if (len + 2 > cap) {
            size_t newcap = cap ? cap * 2 : 128;
            char *newbuf;

            while (len + 2 > newcap)
                newcap *= 2;
            newbuf = realloc(line, newcap);
            if (newbuf == NULL)
                return NULL;
            line = newbuf;
            cap = newcap;
        }

        line[len++] = (char)ch;
        if (ch == '\n')
            break;
    }

    if (len == 0 && ch == EOF)
        return NULL;

    if (line[len - 1] != '\n')
        line[len++] = '\n';
    line[len] = '\0';
    *lenp = len;
    return line;
}

long
armos_xargs_sysconf(int name)
{
    switch (name) {
    case _SC_ARG_MAX:
        return 65536;
    case _SC_PAGESIZE:
        return 4096;
    default:
        errno = EINVAL;
        return -1;
    }
}

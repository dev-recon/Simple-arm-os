#include "armos_compat.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static const char *program_name = "m4";

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "m4";
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

void vwarn(const char *fmt, va_list ap) { vwarn_common(errno, fmt, ap); }
void vwarnx(const char *fmt, va_list ap) { vwarn_common(0, fmt, ap); }

void
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
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
warnc(int code, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn_common(code, fmt, ap);
    va_end(ap);
}

void
verr(int eval, const char *fmt, va_list ap)
{
    vwarn_common(errno, fmt, ap);
    exit(eval);
}

void
verrx(int eval, const char *fmt, va_list ap)
{
    vwarn_common(0, fmt, ap);
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
errx(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verrx(eval, fmt, ap);
    va_end(ap);
}

void
errc(int eval, int code, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn_common(code, fmt, ap);
    va_end(ap);
    exit(eval);
}

intmax_t
strtoi(const char *nptr, char **endptr, int base, intmax_t lo, intmax_t hi,
    int *rstatus)
{
    char *ep;
    int saved_errno;
    int status = 0;
    intmax_t value;

    if (lo > hi) {
        if (rstatus != NULL)
            *rstatus = EINVAL;
        errno = EINVAL;
        if (endptr != NULL)
            *endptr = (char *)nptr;
        return 0;
    }

    errno = 0;
    value = strtoimax(nptr, &ep, base);
    saved_errno = errno;

    if (ep == nptr)
        status = EINVAL;
    else if (saved_errno == ERANGE || value < lo || value > hi)
        status = ERANGE;
    else if (*ep != '\0')
        status = EINVAL;

    if (status == ERANGE) {
        if (value < lo)
            value = lo;
        else if (value > hi)
            value = hi;
    }

    if (endptr != NULL)
        *endptr = ep;
    if (rstatus != NULL)
        *rstatus = status;
    errno = status;
    return value;
}

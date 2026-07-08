#include "armos_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>

#include "libgen.h"
#include "util.h"

static const char *program_name = "sed";

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "sed";
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
warn(const char *fmt, ...)
{
    va_list ap;
    int code = errno;

    va_start(ap, fmt);
    vwarn_common(code, fmt, ap);
    va_end(ap);
}

void
warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn_common(0, fmt, ap);
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
err(int eval, const char *fmt, ...)
{
    va_list ap;
    int code = errno;

    va_start(ap, fmt);
    vwarn_common(code, fmt, ap);
    va_end(ap);
    exit(eval);
}

void
errx(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn_common(0, fmt, ap);
    va_end(ap);
    exit(eval);
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

static void *
check_alloc(void *ptr)
{
    if (ptr == NULL)
        err(1, "malloc");
    return ptr;
}

void *
emalloc(size_t size)
{
    return check_alloc(malloc(size == 0 ? 1 : size));
}

void *
ecalloc(size_t count, size_t size)
{
    if (count != 0 && size > ((size_t)-1) / count)
        errc(1, ENOMEM, "calloc");
    return check_alloc(calloc(count == 0 ? 1 : count, size == 0 ? 1 : size));
}

void *
erealloc(void *ptr, size_t size)
{
    return check_alloc(realloc(ptr, size == 0 ? 1 : size));
}

char *
estrdup(const char *s)
{
    char *copy = strdup(s);

    return check_alloc(copy);
}

#ifndef ARMOS_HAVE_GETLINE
ssize_t
getline(char **linep, size_t *linecap, FILE *stream)
{
    char *line;
    size_t cap;
    size_t len = 0;
    int ch;

    if (linep == NULL || linecap == NULL || stream == NULL) {
        errno = EINVAL;
        return -1;
    }

    line = *linep;
    cap = *linecap;
    if (line == NULL || cap == 0) {
        cap = 128;
        line = malloc(cap);
        if (line == NULL)
            return -1;
    }

    while ((ch = fgetc(stream)) != EOF) {
        if (len + 1 >= cap) {
            char *grown;

            cap *= 2;
            grown = realloc(line, cap);
            if (grown == NULL) {
                if (*linep == NULL)
                    free(line);
                return -1;
            }
            line = grown;
        }

        line[len++] = (char)ch;
        if (ch == '\n')
            break;
    }

    if (len == 0 && ch == EOF) {
        if (*linep == NULL)
            free(line);
        return -1;
    }

    line[len] = '\0';
    *linep = line;
    *linecap = cap;
    return (ssize_t)len;
}
#endif

int
fchown(int fd, uid_t owner, gid_t group)
{
    (void)fd;
    (void)owner;
    (void)group;
    return 0;
}

int
fchmod(int fd, mode_t mode)
{
    (void)fd;
    (void)mode;
    return 0;
}

char *
basename(char *path)
{
    char *end;
    char *base;

    if (path == NULL || *path == '\0')
        return ".";

    end = path + strlen(path) - 1;
    while (end > path && *end == '/')
        *end-- = '\0';

    base = strrchr(path, '/');
    if (base == NULL)
        return path;
    if (base[1] == '\0')
        return "/";
    return base + 1;
}

char *
dirname(char *path)
{
    char *end;
    char *slash;

    if (path == NULL || *path == '\0')
        return ".";

    end = path + strlen(path) - 1;
    while (end > path && *end == '/')
        *end-- = '\0';

    slash = strrchr(path, '/');
    if (slash == NULL)
        return ".";

    while (slash > path && *slash == '/')
        slash--;
    if (slash == path && *slash == '/')
        slash[1] = '\0';
    else
        slash[1] = '\0';

    return path;
}

int
wcwidth(wchar_t wc)
{
    if (wc == L'\0')
        return 0;
    if (wc < 32 || (wc >= 0x7f && wc < 0xa0))
        return -1;
    return 1;
}

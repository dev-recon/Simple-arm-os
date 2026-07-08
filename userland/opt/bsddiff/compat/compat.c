#include "armos_compat.h"

#include <errno.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *program_name = "diff";

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "diff";
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

    line[len] = '\0';
    *lenp = len;
    return line;
}

int
reallocarr(void *ptr, size_t nmemb, size_t size)
{
    void **target = ptr;
    void *newptr;

    if (target == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (nmemb != 0 && size > ((size_t)-1) / nmemb) {
        errno = ENOMEM;
        return -1;
    }

    newptr = realloc(*target, nmemb * size);
    if (newptr == NULL && nmemb * size != 0) {
        errno = ENOMEM;
        return -1;
    }

    *target = newptr;
    return 0;
}

static int
match_bracket(const char **patternp, unsigned char ch)
{
    const char *p = *patternp;
    int negate = 0;
    int matched = 0;

    if (*p == '!' || *p == '^') {
        negate = 1;
        p++;
    }

    while (*p != '\0' && *p != ']') {
        unsigned char first = (unsigned char)*p++;

        if (*p == '-' && p[1] != '\0' && p[1] != ']') {
            unsigned char last;

            p++;
            last = (unsigned char)*p++;
            if (first <= ch && ch <= last)
                matched = 1;
        } else if (first == ch) {
            matched = 1;
        }
    }

    if (*p == ']')
        p++;
    *patternp = p;
    return negate ? !matched : matched;
}

static int
fnmatch_here(const char *pattern, const char *string, int flags)
{
    const char *p = pattern;
    const char *s = string;

    while (*p != '\0') {
        switch (*p) {
        case '?':
            if (*s == '\0' || ((flags & FNM_PATHNAME) && *s == '/'))
                return FNM_NOMATCH;
            p++;
            s++;
            break;
        case '*':
            while (*p == '*')
                p++;
            if (*p == '\0') {
                if ((flags & FNM_PATHNAME) && strchr(s, '/') != NULL)
                    return FNM_NOMATCH;
                return 0;
            }
            for (; *s != '\0'; s++) {
                if ((flags & FNM_PATHNAME) && *s == '/')
                    break;
                if (fnmatch_here(p, s, flags) == 0)
                    return 0;
            }
            return FNM_NOMATCH;
        case '[':
            p++;
            if (*s == '\0' || ((flags & FNM_PATHNAME) && *s == '/'))
                return FNM_NOMATCH;
            if (!match_bracket(&p, (unsigned char)*s))
                return FNM_NOMATCH;
            s++;
            break;
        case '\\':
            if (!(flags & FNM_NOESCAPE) && p[1] != '\0')
                p++;
            /* FALLTHROUGH */
        default:
            if (*p != *s)
                return FNM_NOMATCH;
            p++;
            s++;
            break;
        }
    }

    return *s == '\0' ? 0 : FNM_NOMATCH;
}

int
fnmatch(const char *pattern, const char *string, int flags)
{
    if (pattern == NULL || string == NULL)
        return FNM_NOMATCH;
    return fnmatch_here(pattern, string, flags);
}

int
alphasort(const struct dirent **d1, const struct dirent **d2)
{
    return strcmp((*d1)->d_name, (*d2)->d_name);
}

int
scandir(const char *dirname, struct dirent ***namelist,
    int (*selectfn)(const struct dirent *),
    int (*compar)(const struct dirent **, const struct dirent **))
{
    DIR *dir;
    struct dirent *entry;
    struct dirent **list = NULL;
    size_t count = 0;
    size_t cap = 0;

    if (namelist == NULL) {
        errno = EINVAL;
        return -1;
    }
    *namelist = NULL;

    dir = opendir(dirname);
    if (dir == NULL)
        return -1;

    while ((entry = readdir(dir)) != NULL) {
        struct dirent *copy;

        if (selectfn != NULL && !selectfn(entry))
            continue;

        if (count == cap) {
            size_t newcap = cap ? cap * 2 : 16;
            struct dirent **newlist = realloc(list, newcap * sizeof(*list));

            if (newlist == NULL)
                goto fail;
            list = newlist;
            cap = newcap;
        }

        copy = malloc(sizeof(*copy));
        if (copy == NULL)
            goto fail;
        memcpy(copy, entry, sizeof(*copy));
        list[count++] = copy;
    }

    closedir(dir);

    if (compar != NULL && count > 1)
        qsort(list, count, sizeof(*list),
            (int (*)(const void *, const void *))compar);

    *namelist = list;
    return (int)count;

fail:
    while (count > 0)
        free(list[--count]);
    free(list);
    closedir(dir);
    return -1;
}

ssize_t
pread(int fd, void *buf, size_t nbyte, off_t offset)
{
    off_t oldoff;
    ssize_t nread;
    int saved_errno;

    oldoff = lseek(fd, 0, SEEK_CUR);
    if (oldoff == (off_t)-1)
        return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
        return -1;

    nread = read(fd, buf, nbyte);
    saved_errno = errno;
    if (lseek(fd, oldoff, SEEK_SET) == (off_t)-1 && nread >= 0)
        return -1;
    errno = saved_errno;
    return nread;
}

int
execl(const char *path, const char *arg0, ...)
{
    char *argv[64];
    va_list ap;
    size_t argc = 0;
    const char *arg = arg0;

    va_start(ap, arg0);
    while (arg != NULL) {
        if (argc + 1 >= sizeof(argv) / sizeof(argv[0])) {
            va_end(ap);
            errno = E2BIG;
            return -1;
        }
        argv[argc++] = (char *)(unsigned long)(const void *)arg;
        arg = va_arg(ap, const char *);
    }
    va_end(ap);

    argv[argc] = NULL;
    return execv(path, argv);
}

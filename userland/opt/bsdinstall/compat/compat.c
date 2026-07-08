#include "armos_compat.h"

#undef open
#undef mkstemp
#undef close
#undef fchmod
#undef fchown
#undef vfork

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "md5.h"
#include "rmd160.h"
#include "sha1.h"
#include "sha2.h"

#define FD_PATH_SLOTS 256

static const char *program_name = "install";
static char *fd_paths[FD_PATH_SLOTS];
static char dot_path[] = ".";
static char slash_path[] = "/";

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "install";
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

void
errc(int eval, int code, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn_common(code, fmt, ap);
    va_end(ap);
    exit(eval);
}

static void
track_fd_path(int fd, const char *path)
{
    char *copy;

    if (fd < 0 || fd >= FD_PATH_SLOTS || path == NULL)
        return;

    copy = strdup(path);
    if (copy == NULL)
        return;

    free(fd_paths[fd]);
    fd_paths[fd] = copy;
}

static void
forget_fd_path(int fd)
{
    if (fd < 0 || fd >= FD_PATH_SLOTS)
        return;

    free(fd_paths[fd]);
    fd_paths[fd] = NULL;
}

int
armos_install_open(const char *path, int flags, ...)
{
    mode_t mode;
    int fd;

    if ((flags & O_CREAT) != 0) {
        va_list ap;

        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        fd = open(path, flags, mode);
    } else {
        fd = open(path, flags);
    }

    if (fd >= 0)
        track_fd_path(fd, path);

    return fd;
}

int
armos_install_mkstemp(char *path)
{
    int fd;

    fd = mkstemp(path);
    if (fd >= 0)
        track_fd_path(fd, path);

    return fd;
}

int
armos_install_close(int fd)
{
    forget_fd_path(fd);
    return close(fd);
}

int
armos_install_fchmod(int fd, mode_t mode)
{
    if (fd < 0 || fd >= FD_PATH_SLOTS || fd_paths[fd] == NULL) {
        errno = EBADF;
        return -1;
    }

    return chmod(fd_paths[fd], mode);
}

int
armos_install_fchown(int fd, uid_t owner, gid_t group)
{
    if (fd < 0 || fd >= FD_PATH_SLOTS || fd_paths[fd] == NULL) {
        errno = EBADF;
        return -1;
    }

    return chown(fd_paths[fd], owner, group);
}

int
utimes(const char *path, const struct timeval times[2])
{
    struct utimbuf tb;

    if (times == NULL)
        return utime(path, NULL);

    tb.actime = (time_t)times[0].tv_sec;
    tb.modtime = (time_t)times[1].tv_sec;
    return utime(path, &tb);
}

char *
basename(char *path)
{
    char *end;
    char *base;

    if (path == NULL || *path == '\0')
        return dot_path;

    end = path + strlen(path) - 1;
    while (end > path && *end == '/')
        *end-- = '\0';

    if (end == path && *end == '/')
        return slash_path;

    base = strrchr(path, '/');
    return base == NULL ? path : base + 1;
}

char *
dirname(char *path)
{
    char *end;
    char *slash;

    if (path == NULL || *path == '\0')
        return dot_path;

    end = path + strlen(path) - 1;
    while (end > path && *end == '/')
        *end-- = '\0';

    slash = strrchr(path, '/');
    if (slash == NULL)
        return dot_path;

    while (slash > path && *slash == '/')
        *slash-- = '\0';

    if (slash == path && *slash == '/')
        return slash_path;

    return path;
}

int
setup_getid(const char *dir)
{
    (void)dir;
    return 0;
}

static int
is_octal_mode(const char *mode)
{
    const unsigned char *p = (const unsigned char *)mode;

    if (*p == '\0')
        return 0;

    while (*p != '\0') {
        if (*p < '0' || *p > '7')
            return 0;
        p++;
    }

    return 1;
}

void *
setmode(const char *mode)
{
    if (mode == NULL) {
        errno = EINVAL;
        return NULL;
    }

    return strdup(mode);
}

static mode_t
apply_symbolic_mode(const char *spec, mode_t mode)
{
    const char *p = spec;

    while (*p != '\0') {
        mode_t who = 0;
        mode_t bits = 0;
        int op;

        while (*p == 'u' || *p == 'g' || *p == 'o' || *p == 'a') {
            switch (*p++) {
            case 'u':
                who |= S_IRWXU | S_ISUID;
                break;
            case 'g':
                who |= S_IRWXG | S_ISGID;
                break;
            case 'o':
                who |= S_IRWXO;
                break;
            case 'a':
                who |= S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX;
                break;
            }
        }

        if (who == 0)
            who = S_IRWXU | S_IRWXG | S_IRWXO;

        op = *p++;
        if (op != '+' && op != '-' && op != '=')
            return mode;

        while (*p != '\0' && *p != ',') {
            switch (*p++) {
            case 'r':
                if (who & S_IRWXU)
                    bits |= S_IRUSR;
                if (who & S_IRWXG)
                    bits |= S_IRGRP;
                if (who & S_IRWXO)
                    bits |= S_IROTH;
                break;
            case 'w':
                if (who & S_IRWXU)
                    bits |= S_IWUSR;
                if (who & S_IRWXG)
                    bits |= S_IWGRP;
                if (who & S_IRWXO)
                    bits |= S_IWOTH;
                break;
            case 'x':
            case 'X':
                if (who & S_IRWXU)
                    bits |= S_IXUSR;
                if (who & S_IRWXG)
                    bits |= S_IXGRP;
                if (who & S_IRWXO)
                    bits |= S_IXOTH;
                break;
            case 's':
                if (who & S_ISUID)
                    bits |= S_ISUID;
                if (who & S_ISGID)
                    bits |= S_ISGID;
                break;
            case 't':
                bits |= S_ISVTX;
                break;
            default:
                break;
            }
        }

        switch (op) {
        case '+':
            mode |= bits;
            break;
        case '-':
            mode &= ~bits;
            break;
        case '=':
            mode &= ~(who & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX));
            mode |= bits;
            break;
        }

        if (*p == ',')
            p++;
    }

    return mode & ALLPERMS;
}

mode_t
getmode(const void *set, mode_t mode)
{
    const char *spec = (const char *)set;
    char *end;
    unsigned long parsed;

    if (spec == NULL)
        return mode;

    if (is_octal_mode(spec)) {
        errno = 0;
        parsed = strtoul(spec, &end, 8);
        if (errno == 0 && *end == '\0')
            return (mode_t)(parsed & ALLPERMS);
    }

    return apply_symbolic_mode(spec, mode);
}

static int
parse_unsigned_id(const char *text, unsigned long *id)
{
    char *end;

    if (text == NULL || *text == '\0')
        return -1;

    errno = 0;
    *id = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0')
        return -1;

    return 0;
}

static int
lookup_colon_id(const char *path, const char *name, unsigned field, unsigned long *id)
{
    FILE *fp;
    char line[512];

    fp = fopen(path, "r");
    if (fp == NULL)
        return -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *cursor = line;
        char *save_name = cursor;
        unsigned col = 0;

        while (*cursor != '\0' && *cursor != ':' && *cursor != '\n')
            cursor++;
        if (*cursor != ':')
            continue;
        *cursor++ = '\0';

        if (strcmp(save_name, name) != 0)
            continue;

        while (col < field && *cursor != '\0') {
            if (*cursor++ == ':')
                col++;
        }

        if (col == field) {
            char *end = cursor;

            while (*end != '\0' && *end != ':' && *end != '\n')
                end++;
            *end = '\0';
            if (parse_unsigned_id(cursor, id) == 0) {
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return -1;
}

int
uid_from_user(const char *name, uid_t *uid)
{
    unsigned long id;

    if (name == NULL || uid == NULL)
        return -1;

    if (strcmp(name, "root") == 0) {
        *uid = 0;
        return 0;
    }
    if (strcmp(name, "daemon") == 0) {
        *uid = 1;
        return 0;
    }
    if (strcmp(name, "user") == 0) {
        *uid = 1000;
        return 0;
    }

    if (lookup_colon_id("/etc/passwd", name, 1, &id) == 0) {
        *uid = (uid_t)id;
        return 0;
    }

    return -1;
}

int
gid_from_group(const char *name, gid_t *gid)
{
    unsigned long id;

    if (name == NULL || gid == NULL)
        return -1;

    if (strcmp(name, "wheel") == 0 || strcmp(name, "root") == 0) {
        *gid = 0;
        return 0;
    }
    if (strcmp(name, "daemon") == 0) {
        *gid = 1;
        return 0;
    }
    if (strcmp(name, "user") == 0 || strcmp(name, "users") == 0) {
        *gid = 1000;
        return 0;
    }

    if (lookup_colon_id("/etc/group", name, 1, &id) == 0) {
        *gid = (gid_t)id;
        return 0;
    }

    return -1;
}

int
strsvis(char *dst, const char *src, int flags, const char *extra)
{
    char *out = dst;
    (void)flags;

    while (*src != '\0') {
        unsigned char ch = (unsigned char)*src++;
        int must_escape = !isprint(ch) || (extra != NULL && strchr(extra, ch) != NULL);

        if (!must_escape) {
            *out++ = (char)ch;
            continue;
        }

        switch (ch) {
        case '\n':
            *out++ = '\\';
            *out++ = 'n';
            break;
        case '\t':
            *out++ = '\\';
            *out++ = 't';
            break;
        case '\r':
            *out++ = '\\';
            *out++ = 'r';
            break;
        case '\b':
            *out++ = '\\';
            *out++ = 'b';
            break;
        case '\f':
            *out++ = '\\';
            *out++ = 'f';
            break;
        case '\\':
            *out++ = '\\';
            *out++ = '\\';
            break;
        default:
            *out++ = '\\';
            *out++ = (char)('0' + ((ch >> 6) & 7));
            *out++ = (char)('0' + ((ch >> 3) & 7));
            *out++ = (char)('0' + (ch & 7));
            break;
        }
    }

    *out = '\0';
    return (int)(out - dst);
}

static char *
unsupported_digest(char *buf)
{
    static const char text[] = "unsupported";

    if (buf != NULL) {
        strcpy(buf, text);
        return buf;
    }

    return strdup(text);
}

void MD5Init(MD5_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void MD5Update(MD5_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *MD5End(MD5_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *MD5File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

void RMD160Init(RMD160_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void RMD160Update(RMD160_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *RMD160End(RMD160_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *RMD160File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

void SHA1Init(SHA1_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void SHA1Update(SHA1_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *SHA1End(SHA1_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *SHA1File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

void SHA256_Init(SHA256_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *SHA256_End(SHA256_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *SHA256_File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

void SHA384_Init(SHA384_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void SHA384_Update(SHA384_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *SHA384_End(SHA384_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *SHA384_File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

void SHA512_Init(SHA512_CTX *ctx) { if (ctx) ctx->opaque = 0; }
void SHA512_Update(SHA512_CTX *ctx, const void *data, size_t len) { (void)ctx; (void)data; (void)len; }
char *SHA512_End(SHA512_CTX *ctx, char *buf) { (void)ctx; return unsupported_digest(buf); }
char *SHA512_File(const char *path, char *buf) { (void)path; return unsupported_digest(buf); }

#include "armos_compat.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>

#include "fts.h"
#include "util.h"

#define LINE_INITIAL 128

static const char *program_name = "mtree";

static char root_name[] = "root";
static char daemon_name[] = "daemon";
static char user_name[] = "user";
static char wheel_name[] = "wheel";
static char users_name[] = "users";
static char passwd_placeholder[] = "x";
static char root_home[] = "/";
static char user_home[] = "/home/user";
static char shell_path[] = "/sbin/mash";

static char *empty_members[] = { NULL };
static struct passwd pw_entry;
static struct group gr_entry;

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "mtree";
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

void
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
}

void vwarnx(const char *fmt, va_list ap) { vwarn_common(0, fmt, ap); }

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

void verr(int eval, const char *fmt, va_list ap) { vwarn_common(errno, fmt, ap); exit(eval); }
void verrx(int eval, const char *fmt, va_list ap) { vwarn_common(0, fmt, ap); exit(eval); }

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

int
gethostname(char *name, size_t len)
{
    const char host[] = "armos";

    if (name == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    strlcpy(name, host, len);
    return 0;
}

char *
getlogin(void)
{
    return user_from_uid(getuid(), 1) ? (char *)user_from_uid(getuid(), 1) : user_name;
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

int lchown(const char *path, uid_t owner, gid_t group) { return chown(path, owner, group); }
int lchmod(const char *path, mode_t mode) { return chmod(path, mode); }

int
lchflags(const char *path, unsigned long flags)
{
    (void)path;
    if (flags == 0)
        return 0;
    errno = ENOSYS;
    return -1;
}

int
mkfifo(const char *path, mode_t mode)
{
    return mknod(path, S_IFIFO | mode, 0);
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
setup_getid(const char *dir)
{
    (void)dir;
    return 0;
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

const char *
user_from_uid(uid_t uid, int nouser)
{
    static char buf[32];

    switch ((unsigned)uid) {
    case 0:
        return root_name;
    case 1:
        return daemon_name;
    case 1000:
        return user_name;
    default:
        if (!nouser)
            return NULL;
        snprintf(buf, sizeof(buf), "%u", (unsigned)uid);
        return buf;
    }
}

const char *
group_from_gid(gid_t gid, int nogroup)
{
    static char buf[32];

    switch ((unsigned)gid) {
    case 0:
        return wheel_name;
    case 1:
        return daemon_name;
    case 1000:
        return users_name;
    default:
        if (!nogroup)
            return NULL;
        snprintf(buf, sizeof(buf), "%u", (unsigned)gid);
        return buf;
    }
}

struct passwd *
getpwuid(uid_t uid)
{
    const char *name = user_from_uid(uid, 0);

    if (name == NULL)
        return NULL;

    memset(&pw_entry, 0, sizeof(pw_entry));
    pw_entry.pw_name = (char *)name;
    pw_entry.pw_passwd = passwd_placeholder;
    pw_entry.pw_uid = uid;
    pw_entry.pw_gid = uid == 0 ? 0 : 1000;
    pw_entry.pw_dir = uid == 0 ? root_home : user_home;
    pw_entry.pw_shell = shell_path;
    return &pw_entry;
}

struct passwd *
getpwnam(const char *name)
{
    uid_t uid;

    if (uid_from_user(name, &uid) < 0)
        return NULL;
    return getpwuid(uid);
}

struct group *
getgrgid(gid_t gid)
{
    const char *name = group_from_gid(gid, 0);

    if (name == NULL)
        return NULL;

    memset(&gr_entry, 0, sizeof(gr_entry));
    gr_entry.gr_name = (char *)name;
    gr_entry.gr_passwd = passwd_placeholder;
    gr_entry.gr_gid = gid;
    gr_entry.gr_mem = empty_members;
    return &gr_entry;
}

struct group *
getgrnam(const char *name)
{
    gid_t gid;

    if (gid_from_group(name, &gid) < 0)
        return NULL;
    return getgrgid(gid);
}

char *
flags_to_string(unsigned long flags, const char *def)
{
    (void)flags;
    return strdup(def != NULL ? def : "none");
}

int
string_to_flags(char **stringp, unsigned long *setp, unsigned long *clrp)
{
    if (stringp == NULL || *stringp == NULL)
        return -1;
    if (strcmp(*stringp, "none") != 0) {
        errno = EINVAL;
        return -1;
    }
    if (setp != NULL)
        *setp = 0;
    if (clrp != NULL)
        *clrp = 0;
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

        if (op == '+')
            mode |= bits;
        else if (op == '-')
            mode &= ~bits;
        else {
            mode &= ~(who & ALLPERMS);
            mode |= bits;
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
append_char(char **buf, size_t *cap, size_t *len, char ch)
{
    char *grown;

    if (*len + 2 <= *cap) {
        (*buf)[(*len)++] = ch;
        return 0;
    }

    *cap *= 2;
    grown = realloc(*buf, *cap);
    if (grown == NULL)
        return -1;
    *buf = grown;
    (*buf)[(*len)++] = ch;
    return 0;
}

static void
strip_comment(char *line)
{
    bool escaped = false;

    for (; *line != '\0'; line++) {
        if (!escaped && *line == '#') {
            *line = '\0';
            return;
        }
        escaped = !escaped && *line == '\\';
        if (*line != '\\')
            escaped = false;
    }
}

static void
unescape_line(char *line)
{
    char *src = line;
    char *dst = line;

    while (*src != '\0') {
        if (*src == '\\' && src[1] != '\0')
            src++;
        *dst++ = *src++;
    }
    *dst = '\0';
}

char *
fparseln(FILE *fp, size_t *lenp, size_t *linenop, const char delim[3], int flags)
{
    char *buf;
    size_t cap = LINE_INITIAL;
    size_t len = 0;
    int ch;
    (void)delim;

    if (fp == NULL) {
        errno = EINVAL;
        return NULL;
    }

    buf = malloc(cap);
    if (buf == NULL)
        return NULL;

    while ((ch = fgetc(fp)) != EOF) {
        if (ch == '\n')
            break;
        if (ch == '\r')
            continue;
        if (append_char(&buf, &cap, &len, (char)ch) < 0) {
            free(buf);
            return NULL;
        }
    }

    if (ch == EOF && len == 0) {
        free(buf);
        return NULL;
    }

    buf[len] = '\0';
    if (linenop != NULL)
        (*linenop)++;

    if (flags & FPARSELN_UNESCCOMM) {
        strip_comment(buf);
        len = strlen(buf);
    }
    if (flags & FPARSELN_UNESCALL) {
        unescape_line(buf);
        len = strlen(buf);
    }

    if (lenp != NULL)
        *lenp = len;
    return buf;
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

int
strunvis(char *dst, const char *src)
{
    char *out = dst;

    while (*src != '\0') {
        if (*src != '\\') {
            *out++ = *src++;
            continue;
        }

        src++;
        if (*src >= '0' && *src <= '7') {
            int val = 0;
            int count = 0;
            while (count < 3 && *src >= '0' && *src <= '7') {
                val = (val << 3) + (*src - '0');
                src++;
                count++;
            }
            *out++ = (char)val;
            continue;
        }

        switch (*src) {
        case 'n':
            *out++ = '\n';
            src++;
            break;
        case 't':
            *out++ = '\t';
            src++;
            break;
        case 'r':
            *out++ = '\r';
            src++;
            break;
        case '\0':
            *out++ = '\\';
            break;
        default:
            *out++ = *src++;
            break;
        }
    }

    *out = '\0';
    return 0;
}

static char *
path_join(const char *parent, const char *name)
{
    char *path;
    const char *prefix = parent;
    const char *slash = "/";

    if (strcmp(parent, ".") == 0)
        slash = "/";
    if (asprintf(&path, "%s%s%s", prefix, slash, name) < 0)
        return NULL;
    return path;
}

static FTSENT *
fts_alloc_entry(const char *path, const char *name, FTSENT *parent, short level)
{
    FTSENT *ent = calloc(1, sizeof(*ent));

    if (ent == NULL)
        return NULL;

    ent->fts_path = strdup(path);
    ent->fts_accpath = strdup(path);
    ent->fts_name = strdup(name);
    ent->fts_statp = calloc(1, sizeof(*ent->fts_statp));
    if (ent->fts_path == NULL || ent->fts_accpath == NULL ||
        ent->fts_name == NULL || ent->fts_statp == NULL) {
        free(ent->fts_path);
        free(ent->fts_accpath);
        free(ent->fts_name);
        free(ent->fts_statp);
        free(ent);
        return NULL;
    }

    ent->fts_parent = parent;
    ent->fts_level = level;
    ent->fts_pathlen = (unsigned short)strlen(ent->fts_path);
    ent->fts_namelen = (unsigned short)strlen(ent->fts_name);
    return ent;
}

static int
fts_push_entry(FTS *ftsp, FTSENT *ent)
{
    FTSENT **grown;

    if (ftsp->entry_count < ftsp->entry_cap) {
        ftsp->entries[ftsp->entry_count++] = ent;
        return 0;
    }

    ftsp->entry_cap = ftsp->entry_cap == 0 ? 64 : ftsp->entry_cap * 2;
    grown = realloc(ftsp->entries, ftsp->entry_cap * sizeof(ftsp->entries[0]));
    if (grown == NULL)
        return -1;
    ftsp->entries = grown;
    ftsp->entries[ftsp->entry_count++] = ent;
    return 0;
}

static int
fts_stat_path(FTS *ftsp, FTSENT *ent)
{
    int ret;

    if (ftsp->options & FTS_LOGICAL)
        ret = stat(ent->fts_accpath, ent->fts_statp);
    else
        ret = lstat(ent->fts_accpath, ent->fts_statp);

    if (ret == 0) {
        if (S_ISDIR(ent->fts_statp->st_mode))
            ent->fts_info = FTS_D;
        else if (S_ISLNK(ent->fts_statp->st_mode))
            ent->fts_info = FTS_SL;
        else if (S_ISREG(ent->fts_statp->st_mode))
            ent->fts_info = FTS_F;
        else
            ent->fts_info = FTS_DEFAULT;
        return 0;
    }

    ent->fts_errno = errno;
    ent->fts_info = FTS_NS;
    return -1;
}

static int
fts_build(FTS *ftsp, FTSENT *parent, const char *path, const char *name, short level)
{
    FTSENT *ent;
    FTSENT *last_child = NULL;
    DIR *dir;
    struct dirent *de;
    FTSENT **children = NULL;
    size_t child_count = 0;
    size_t child_cap = 0;
    size_t i;

    ent = fts_alloc_entry(path, name, parent, level);
    if (ent == NULL)
        return -1;
    if (fts_stat_path(ftsp, ent) < 0) {
        if (fts_push_entry(ftsp, ent) < 0)
            return -1;
        return 0;
    }

    if ((ftsp->options & FTS_XDEV) && level > 0 && ent->fts_statp->st_dev != ftsp->root_dev) {
        if (fts_push_entry(ftsp, ent) < 0)
            return -1;
        return 0;
    }

    if (!S_ISDIR(ent->fts_statp->st_mode)) {
        if (fts_push_entry(ftsp, ent) < 0)
            return -1;
        return 0;
    }

    if (fts_push_entry(ftsp, ent) < 0)
        return -1;

    dir = opendir(path);
    if (dir == NULL) {
        ent->fts_errno = errno;
        ent->fts_info = FTS_DNR;
    } else {
        while ((de = readdir(dir)) != NULL) {
            FTSENT *child;
            FTSENT **grown;
            char *child_path;

            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;

            child_path = path_join(path, de->d_name);
            if (child_path == NULL) {
                closedir(dir);
                return -1;
            }

            child = fts_alloc_entry(child_path, de->d_name, ent, level + 1);
            free(child_path);
            if (child == NULL) {
                closedir(dir);
                return -1;
            }
            (void)fts_stat_path(ftsp, child);

            if (child_count == child_cap) {
                child_cap = child_cap == 0 ? 16 : child_cap * 2;
                grown = realloc(children, child_cap * sizeof(children[0]));
                if (grown == NULL) {
                    closedir(dir);
                    return -1;
                }
                children = grown;
            }
            children[child_count++] = child;
        }
        closedir(dir);

        if (ftsp->compar != NULL && child_count > 1)
            qsort(children, child_count, sizeof(children[0]),
                (int (*)(const void *, const void *))ftsp->compar);

        for (i = 0; i < child_count; i++) {
            FTSENT *child = children[i];
            FTSENT *linked_child = child;
            char *child_path = strdup(child->fts_path);
            char *child_name = strdup(child->fts_name);

            if (S_ISDIR(child->fts_statp->st_mode)) {
                size_t first_new_entry = ftsp->entry_count;

                free(child->fts_path);
                free(child->fts_accpath);
                free(child->fts_name);
                free(child->fts_statp);
                free(child);
                if (child_path == NULL || child_name == NULL) {
                    free(child_path);
                    free(child_name);
                    free(children);
                    return -1;
                }
                if (fts_build(ftsp, ent, child_path, child_name, level + 1) < 0) {
                    free(child_path);
                    free(child_name);
                    free(children);
                    return -1;
                }
                linked_child = ftsp->entries[first_new_entry];
            } else {
                if (fts_push_entry(ftsp, child) < 0) {
                    free(child_path);
                    free(child_name);
                    free(children);
                    return -1;
                }
            }

            if (last_child == NULL)
                ent->fts_child = linked_child;
            else
                last_child->fts_link = linked_child;
            last_child = linked_child;

            free(child_path);
            free(child_name);
        }
    }

    free(children);

    {
        FTSENT *post = fts_alloc_entry(path, name, parent, level);
        if (post == NULL)
            return -1;
        memcpy(post->fts_statp, ent->fts_statp, sizeof(*post->fts_statp));
        post->fts_info = FTS_DP;
        post->fts_child = ent->fts_child;
        if (fts_push_entry(ftsp, post) < 0)
            return -1;
    }

    return 0;
}

FTS *
fts_open(char * const *argv, int options, int (*compar)(const FTSENT **, const FTSENT **))
{
    FTS *ftsp;
    int i;

    if (argv == NULL || argv[0] == NULL) {
        errno = EINVAL;
        return NULL;
    }

    ftsp = calloc(1, sizeof(*ftsp));
    if (ftsp == NULL)
        return NULL;
    ftsp->options = options;
    ftsp->compar = compar;

    for (i = 0; argv[i] != NULL; i++) {
        const char *path = argv[i];
        const char *name = strrchr(path, '/');
        struct stat st;

        name = name == NULL ? path : name + 1;
        if (stat(path, &st) == 0 && i == 0)
            ftsp->root_dev = st.st_dev;
        if (fts_build(ftsp, NULL, path, name, 0) < 0) {
            fts_close(ftsp);
            return NULL;
        }
    }

    return ftsp;
}

static bool
path_is_under(const char *path, const char *root)
{
    size_t len = strlen(root);

    return strcmp(path, root) == 0 || (strncmp(path, root, len) == 0 && path[len] == '/');
}

FTSENT *
fts_read(FTS *ftsp)
{
    if (ftsp == NULL) {
        errno = EINVAL;
        return NULL;
    }

    while (ftsp->index < ftsp->entry_count) {
        FTSENT *ent = ftsp->entries[ftsp->index++];

        if (ftsp->skip_path != NULL) {
            if (path_is_under(ent->fts_path, ftsp->skip_path)) {
                continue;
            }
            free(ftsp->skip_path);
            ftsp->skip_path = NULL;
        }

        ftsp->current = ent;
        errno = 0;
        return ent;
    }

    errno = 0;
    return NULL;
}

FTSENT *
fts_children(FTS *ftsp, int instr)
{
    (void)instr;

    if (ftsp == NULL || ftsp->current == NULL) {
        errno = EINVAL;
        return NULL;
    }

    errno = 0;
    return ftsp->current->fts_child;
}

int
fts_set(FTS *ftsp, FTSENT *f, int instr)
{
    if (ftsp == NULL || f == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (instr == FTS_SKIP) {
        free(ftsp->skip_path);
        ftsp->skip_path = strdup(f->fts_path);
        ftsp->skip_level = f->fts_level;
        return ftsp->skip_path == NULL ? -1 : 0;
    }

    return 0;
}

int
fts_close(FTS *ftsp)
{
    size_t i;

    if (ftsp == NULL)
        return 0;

    for (i = 0; i < ftsp->entry_count; i++) {
        FTSENT *ent = ftsp->entries[i];
        free(ent->fts_path);
        free(ent->fts_accpath);
        free(ent->fts_name);
        free(ent->fts_statp);
        free(ent);
    }

    free(ftsp->skip_path);
    free(ftsp->entries);
    free(ftsp);
    return 0;
}

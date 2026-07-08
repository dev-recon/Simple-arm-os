#include "armos_compat.h"

#undef getline

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

static const char *program_name = "patch";
int optreset;

#define POPEN_SLOTS 256
static pid_t popen_pids[POPEN_SLOTS];

void
setprogname(const char *name)
{
    const char *slash;

    if (name == NULL || *name == '\0') {
        program_name = "patch";
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
        *slash-- = '\0';

    if (slash == path && *slash == '/')
        return "/";

    *slash = '\0';
    return path;
}

FILE *
popen(const char *command, const char *mode)
{
    int fds[2];
    pid_t pid;
    int parent_fd;
    int child_fd;
    int child_target;
    FILE *fp;

    if (command == NULL || mode == NULL || (mode[0] != 'r' && mode[0] != 'w') || mode[1] != '\0') {
        errno = EINVAL;
        return NULL;
    }

    if (pipe(fds) < 0)
        return NULL;

    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return NULL;
    }

    if (pid == 0) {
        char *argv[4];

        if (mode[0] == 'r') {
            child_fd = fds[1];
            child_target = STDOUT_FILENO;
            close(fds[0]);
        } else {
            child_fd = fds[0];
            child_target = STDIN_FILENO;
            close(fds[1]);
        }

        if (child_fd != child_target) {
            dup2(child_fd, child_target);
            close(child_fd);
        }

        argv[0] = "mash";
        argv[1] = "-c";
        argv[2] = (char *)(unsigned long)(const void *)command;
        argv[3] = NULL;
        execv("/sbin/mash", argv);
        _exit(127);
    }

    if (mode[0] == 'r') {
        parent_fd = fds[0];
        close(fds[1]);
    } else {
        parent_fd = fds[1];
        close(fds[0]);
    }

    fp = fdopen(parent_fd, mode);
    if (fp == NULL) {
        close(parent_fd);
        return NULL;
    }

    if (parent_fd >= 0 && parent_fd < POPEN_SLOTS)
        popen_pids[parent_fd] = pid;
    return fp;
}

int
pclose(FILE *stream)
{
    int fd;
    pid_t pid;
    int status;

    if (stream == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = fileno(stream);
    if (fd < 0 || fd >= POPEN_SLOTS || popen_pids[fd] <= 0) {
        errno = EBADF;
        return -1;
    }

    pid = popen_pids[fd];
    popen_pids[fd] = 0;
    if (fclose(stream) != 0)
        return -1;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return status;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: newlib-port/syscalls.c
 * Layer: Userland / newlib port
 * Description: Newlib syscall glue and ArmOS ABI adaptation layer.
 */

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/times.h>
#include <sys/types.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>

#ifndef O_RDONLY
#define O_RDONLY 0
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

extern long sys_read(int fd, void *buf, unsigned long count);
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_open(const char *pathname, int flags, int mode);
extern long sys_creat(const char *pathname, int mode);
extern long sys_close(int fd);
extern long sys_mount(const char *source, const char *target,
                      const char *filesystemtype, unsigned long mountflags,
                      const void *data);
extern long sys_umount(const char *target);
extern long sys_time(void *tloc);
extern long sys_lseek(int fd, long offset, int whence);
extern long sys_unlink(const char *pathname);
extern long sys_rename(const char *oldpath, const char *newpath);
extern long sys_mkdir(const char *pathname, int mode);
extern long sys_rmdir(const char *pathname);
extern long sys_symlink(const char *target, const char *linkpath);
extern long sys_readlink(const char *pathname, char *buf, unsigned long bufsiz);
extern long sys_ftruncate(int fd, long length);
extern long sys_truncate(const char *pathname, long length);
extern long sys_fsync(int fd);
extern long sys_statfs(const char *path, void *buf);
extern long sys_stat(const char *pathname, void *st);
extern long sys_lstat(const char *pathname, void *st);
extern long sys_fstat(int fd, void *st);
extern long sys_gettimeofday(struct timeval *tv, void *tz);
extern long sys_ioctl(int fd, unsigned long request, void *arg);
extern long sys_fcntl(int fd, int cmd, long arg);
extern long sys_kill(int pid, int sig);
extern long sys_getpid(void);
extern long sys_getppid(void);
extern long sys_setuid(int uid);
extern long sys_getuid(void);
extern long sys_geteuid(void);
extern long sys_setgid(int gid);
extern long sys_getgid(void);
extern long sys_getegid(void);
extern long sys_nice(int inc);
extern long sys_getpriority(int which, int who);
extern long sys_setpriority(int which, int who, int prio);
extern long sys_getpgrp(void);
extern long sys_setpgid(int pid, int pgid);
extern long sys_setsid(void);
extern long sys_getsid(int pid);
extern long sys_sigprocmask(int how, const void *set, void *oldset);
extern long sys_sigpending(void *set);
extern long sys_sigsuspend(const void *mask);
extern long sys_times(void *buf);
extern long sys_alarm(unsigned int seconds);
extern long sys_pause(void);
extern long sys_utime(const char *pathname, const void *times);
extern long sys_fork(void);
extern long sys_execve(const char *pathname, char *const argv[], char *const envp[]);
extern long sys_waitpid(int pid, int *status, int options);
extern long sys_wait4(int pid, int *status, int options, void *rusage);
extern long sys_brk(unsigned long brk);
extern long sys_link(const char *oldpath, const char *newpath);
extern long sys_access(const char *pathname, int mode);
extern long sys_sync(void);
extern long sys_chdir(const char *path);
extern long sys_getcwd(char *buf, unsigned long size);
extern long sys_chmod(const char *path, int mode);
extern long sys_chown(const char *path, int owner, int group);
extern long sys_umask(int mask);
extern long sys_pipe(int pipefd[2]);
extern long sys_dup(int oldfd);
extern long sys_dup2(int oldfd, int newfd);
extern long sys_getdents(int fd, void *dirp, unsigned long count);
extern long sys_nanosleep(const struct timespec *req, struct timespec *rem);
extern long sys_mknod(const char *pathname, int mode, unsigned long dev);
extern long sys_mmap(void *addr, unsigned long length, int prot, int flags, int fd);
extern long sys_munmap(void *addr, unsigned long length);
extern long sys_mprotect(void *addr, unsigned long length, int prot);
extern long sys_select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);
extern long sys_poll(void *fds, unsigned long nfds, int timeout);
extern long sys_readv(int fd, const void *iov, int iovcnt);
extern long sys_writev(int fd, const void *iov, int iovcnt);
extern long sys_getrusage(int who, void *usage);
extern long sys_uname(void *name);
extern long sys_stty(int request, int value, int value2);
extern long sys_gtty(int request, int value);
extern long sys_sigaction(int sig, const void *act, void *oldact);
extern long sys_sysinfo(void *resp);
extern long sys_shm_open(const char *name, unsigned long size, int flags);
extern long sys_shm_unlink(const char *name);
extern long sys_shm_map(int id, void *addr, int flags);
extern long sys_shm_unmap(void *addr, unsigned long size);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_bind(int sockfd, const void *addr, unsigned long addrlen);
extern long sys_connect(int sockfd, const void *addr, unsigned long addrlen);
extern long sys_listen(int sockfd, int backlog);
extern long sys_accept(int sockfd, void *addr, unsigned long *addrlen);
extern void sys_exit(int status);
extern void __signal_return_trampoline(void);

char *__env[1] = { 0 };
char **environ = __env;
static const char *program_name = "program";

#define ARMOS_OPEN_MAX 256

#define TTY_STTY_SET_FOREGROUND_PGID 1
#define TTY_GTTY_GET_FOREGROUND_PGID 1
#define TTY_STTY_SET_FOREGROUND_PGID_FD 2
#define TTY_GTTY_GET_FOREGROUND_PGID_FD 2

#define OS_SIGBUS   7
#define OS_SIGUSR1  10
#define OS_SIGUSR2  12
#define OS_SIGCHLD  17
#define OS_SIGCONT  18
#define OS_SIGSTOP  19
#define OS_SIGTSTP  20

#ifndef TCGETS
#define TCGETS  0x5401
#define TCSETS  0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TCFLSH  0x540B
#endif

#ifndef TCSANOW
#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2
#endif

#ifndef TCIFLUSH
#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2
#endif

struct armos_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[32];
    uint32_t c_ispeed;
    uint32_t c_ospeed;
};

struct os_stat {
    uint32_t st_dev;
    uint32_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t st_rdev;
    int32_t  st_size;
    uint32_t st_blksize;
    uint32_t st_blocks;
    uint32_t os_atime;
    uint32_t os_mtime;
    uint32_t os_ctime;
};

struct os_timeval {
    int32_t tv_sec;
    uint32_t tv_usec;
};

struct os_timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

struct os_sigaction {
    void (*sa_handler)(int);
    uint32_t sa_mask;
    int sa_flags;
    void (*sa_restorer)(void);
};

typedef unsigned long nfds_t;

struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

struct __dirstream {
    int fd;
    size_t pos;
    size_t len;
    struct dirent current;
    char buffer[4096];
};

static int ret_errno(long ret)
{
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return (int)ret;
}

void __armos_init_program_name(const char *argv0)
{
    const char *base;

    if (!argv0 || !*argv0)
        return;

    base = strrchr(argv0, '/');
    program_name = (base && base[1]) ? base + 1 : argv0;
}

const char *getprogname(void)
{
    return program_name;
}

int getdtablesize(void)
{
    return ARMOS_OPEN_MAX;
}

char *dirname(char *path)
{
    static char dot[] = ".";
    char *end;
    char *slash;

    if (!path || !*path)
        return dot;

    end = path + strlen(path);
    while (end > path + 1 && end[-1] == '/')
        *--end = '\0';

    slash = strrchr(path, '/');
    if (!slash)
        return dot;

    if (slash == path) {
        slash[1] = '\0';
        return path;
    }

    while (slash > path && slash[-1] == '/')
        slash--;
    *slash = '\0';
    return path;
}

static int passwd_fd = -1;
static char passwd_line[512];
static struct passwd passwd_entry;

static char *passwd_next_field(char **cursor)
{
    char *start;
    char *colon;

    if (!cursor || !*cursor)
        return NULL;

    start = *cursor;
    colon = strchr(start, ':');
    if (colon) {
        *colon = '\0';
        *cursor = colon + 1;
    } else {
        *cursor = NULL;
    }

    return start;
}

static int passwd_read_line(char *buf, size_t buf_size)
{
    size_t pos = 0;
    char ch;
    long ret;
    int saw_data = 0;

    if (passwd_fd < 0 || buf_size == 0)
        return 0;

    for (;;) {
        ret = sys_read(passwd_fd, &ch, 1);
        if (ret < 0) {
            errno = (int)-ret;
            return -1;
        }
        if (ret == 0)
            break;

        saw_data = 1;
        if (ch == '\n')
            break;
        if (pos + 1 < buf_size)
            buf[pos++] = ch;
    }

    if (!saw_data)
        return 0;

    buf[pos] = '\0';
    return 1;
}

static struct passwd *passwd_parse_line(char *line)
{
    char *cursor = line;
    char *name = passwd_next_field(&cursor);
    char *password = passwd_next_field(&cursor);
    char *uid = passwd_next_field(&cursor);
    char *gid = passwd_next_field(&cursor);
    char *gecos = passwd_next_field(&cursor);
    char *home = passwd_next_field(&cursor);
    char *shell = passwd_next_field(&cursor);

    if (!name || !password || !uid || !gid || !gecos || !home || !shell)
        return NULL;

    passwd_entry.pw_name = name;
    passwd_entry.pw_passwd = password;
    passwd_entry.pw_uid = (uid_t)strtoul(uid, NULL, 10);
    passwd_entry.pw_gid = (gid_t)strtoul(gid, NULL, 10);
    passwd_entry.pw_comment = gecos;
    passwd_entry.pw_gecos = gecos;
    passwd_entry.pw_dir = home;
    passwd_entry.pw_shell = shell;
    return &passwd_entry;
}

void setpwent(void)
{
    long ret;

    if (passwd_fd >= 0) {
        sys_lseek(passwd_fd, 0, SEEK_SET);
        return;
    }

    ret = sys_open("/etc/passwd", O_RDONLY, 0);
    if (ret < 0) {
        errno = (int)-ret;
        passwd_fd = -1;
        return;
    }
    passwd_fd = (int)ret;
}

void endpwent(void)
{
    if (passwd_fd >= 0) {
        sys_close(passwd_fd);
        passwd_fd = -1;
    }
}

struct passwd *getpwent(void)
{
    int ret;
    struct passwd *entry;

    if (passwd_fd < 0)
        setpwent();
    if (passwd_fd < 0)
        return NULL;

    while ((ret = passwd_read_line(passwd_line, sizeof(passwd_line))) > 0) {
        entry = passwd_parse_line(passwd_line);
        if (entry)
            return entry;
    }

    return NULL;
}

struct passwd *getpwuid(uid_t uid)
{
    struct passwd *entry;

    setpwent();
    while ((entry = getpwent()) != NULL) {
        if (entry->pw_uid == uid) {
            endpwent();
            return entry;
        }
    }
    endpwent();
    return NULL;
}

struct passwd *getpwnam(const char *name)
{
    struct passwd *entry;

    if (!name)
        return NULL;

    setpwent();
    while ((entry = getpwent()) != NULL) {
        if (strcmp(entry->pw_name, name) == 0) {
            endpwent();
            return entry;
        }
    }
    endpwent();
    return NULL;
}

static int append_path_component(char *dst, size_t dst_size,
                                 const char *component, size_t len)
{
    size_t cur;

    if (len == 0 || (len == 1 && component[0] == '.'))
        return 0;

    if (len == 2 && component[0] == '.' && component[1] == '.') {
        char *slash;
        cur = strlen(dst);
        if (cur <= 1) {
            dst[0] = '/';
            dst[1] = '\0';
            return 0;
        }
        slash = strrchr(dst, '/');
        if (!slash || slash == dst)
            dst[1] = '\0';
        else
            *slash = '\0';
        return 0;
    }

    cur = strlen(dst);
    if (cur > 1) {
        if (cur + 1 >= dst_size)
            return -1;
        dst[cur++] = '/';
        dst[cur] = '\0';
    }

    if (cur + len >= dst_size)
        return -1;

    memcpy(dst + cur, component, len);
    dst[cur + len] = '\0';
    return 0;
}

static int normalize_absolute_path(const char *path, char *dst, size_t dst_size)
{
    const char *p = path;

    if (!path || path[0] != '/' || dst_size < 2)
        return -1;

    dst[0] = '/';
    dst[1] = '\0';

    while (*p) {
        const char *start;
        size_t len;

        while (*p == '/')
            p++;
        start = p;
        while (*p && *p != '/')
            p++;
        len = (size_t)(p - start);

        if (append_path_component(dst, dst_size, start, len) < 0)
            return -1;
    }

    return 0;
}

static int signal_newlib_to_os(int sig)
{
    switch (sig) {
    case SIGBUS:
        return OS_SIGBUS;
    case SIGUSR1:
        return OS_SIGUSR1;
    case SIGUSR2:
        return OS_SIGUSR2;
    case SIGCHLD:
        return OS_SIGCHLD;
    case SIGCONT:
        return OS_SIGCONT;
    case SIGSTOP:
        return OS_SIGSTOP;
#ifdef SIGTSTP
    case SIGTSTP:
        return OS_SIGTSTP;
#endif
    default:
        return sig;
    }
}

static int signal_os_to_newlib(int sig)
{
    switch (sig) {
    case OS_SIGBUS:
        return SIGBUS;
    case OS_SIGUSR1:
        return SIGUSR1;
    case OS_SIGUSR2:
        return SIGUSR2;
    case OS_SIGCHLD:
        return SIGCHLD;
    case OS_SIGCONT:
        return SIGCONT;
    case OS_SIGSTOP:
        return SIGSTOP;
#ifdef SIGTSTP
    case OS_SIGTSTP:
        return SIGTSTP;
#endif
    default:
        return sig;
    }
}

static int wait_status_os_to_newlib(int status)
{
    if ((status & 0xff) == 0x7f) {
        int sig = signal_os_to_newlib((status >> 8) & 0xff);
        return 0x7f | ((sig & 0xff) << 8);
    }

    if ((status & 0x7f) != 0) {
        int sig = signal_os_to_newlib(status & 0x7f);
        return sig & 0x7f;
    }

    return status;
}

static uint32_t sigset_newlib_to_os(sigset_t set)
{
    uint32_t out = 0;

    for (int sig = 1; sig < 32; sig++) {
        if ((uint32_t)set & (1u << sig)) {
            int os_sig = signal_newlib_to_os(sig);
            if (os_sig > 0 && os_sig < 32)
                out |= (1u << os_sig);
        }
    }

    return out;
}

static sigset_t sigset_os_to_newlib(uint32_t set)
{
    sigset_t out = 0;

    for (int sig = 1; sig < 32; sig++) {
        if (set & (1u << sig)) {
            int nl_sig = signal_os_to_newlib(sig);
            if (nl_sig > 0 && nl_sig < 32)
                out |= (sigset_t)(1u << nl_sig);
        }
    }

    return out;
}

static void copy_stat(struct stat *dst, const struct os_stat *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = src->st_dev;
    dst->st_ino = src->st_ino;
    dst->st_mode = src->st_mode;
    dst->st_nlink = src->st_nlink;
    dst->st_uid = src->st_uid;
    dst->st_gid = src->st_gid;
    dst->st_rdev = src->st_rdev;
    dst->st_size = src->st_size;
    dst->st_blksize = src->st_blksize;
    dst->st_blocks = src->st_blocks;
    dst->st_atime = src->os_atime;
    dst->st_mtime = src->os_mtime;
    dst->st_ctime = src->os_ctime;
}

int _read(int fd, void *buf, size_t count)
{
    return ret_errno(sys_read(fd, buf, count));
}

int _write(int fd, const void *buf, size_t count)
{
    return ret_errno(sys_write(fd, buf, count));
}

int _open(const char *pathname, int flags, int mode)
{
    return ret_errno(sys_open(pathname, flags, mode));
}

int creat(const char *pathname, mode_t mode)
{
    return ret_errno(sys_creat(pathname, (int)mode));
}

int _close(int fd)
{
    return ret_errno(sys_close(fd));
}

int mount(const char *source, const char *target, const char *filesystemtype,
          unsigned long mountflags, const void *data)
{
    return ret_errno(sys_mount(source, target, filesystemtype, mountflags, data));
}

int umount(const char *target)
{
    return ret_errno(sys_umount(target));
}

off_t _lseek(int fd, off_t offset, int whence)
{
    long ret = sys_lseek(fd, offset, whence);
    if (ret < 0) {
        errno = (int)-ret;
        return (off_t)-1;
    }
    return (off_t)ret;
}

int _unlink(const char *pathname)
{
    return ret_errno(sys_unlink(pathname));
}

int _link(const char *oldpath, const char *newpath)
{
    return ret_errno(sys_link(oldpath, newpath));
}

int _rename(const char *oldpath, const char *newpath)
{
    return ret_errno(sys_rename(oldpath, newpath));
}

int mkdir(const char *pathname, mode_t mode)
{
    return ret_errno(sys_mkdir(pathname, (int)mode));
}

int rmdir(const char *pathname)
{
    return ret_errno(sys_rmdir(pathname));
}

int symlink(const char *target, const char *linkpath)
{
    return ret_errno(sys_symlink(target, linkpath));
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    long ret = sys_readlink(pathname, buf, bufsiz);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return (ssize_t)ret;
}

int _stat(const char *pathname, struct stat *st)
{
    struct os_stat os_st;
    long ret;

    if (!st) {
        errno = EFAULT;
        return -1;
    }

    ret = sys_stat(pathname, &os_st);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }

    copy_stat(st, &os_st);
    return 0;
}

int _lstat(const char *pathname, struct stat *st)
{
    struct os_stat os_st;
    long ret;

    if (!st) {
        errno = EFAULT;
        return -1;
    }

    ret = sys_lstat(pathname, &os_st);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }

    copy_stat(st, &os_st);
    return 0;
}

int _fstat(int fd, struct stat *st)
{
    struct os_stat os_st;
    long ret;

    if (!st) {
        errno = EFAULT;
        return -1;
    }

    ret = sys_fstat(fd, &os_st);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }

    copy_stat(st, &os_st);
    return 0;
}

int stat(const char *pathname, struct stat *st)
{
    return _stat(pathname, st);
}

int statfs(const char *path, void *buf)
{
    return ret_errno(sys_statfs(path, buf));
}

int uname(struct utsname *name)
{
    if (!name) {
        errno = EFAULT;
        return -1;
    }
    return ret_errno(sys_uname(name));
}

int lstat(const char *pathname, struct stat *st)
{
    return _lstat(pathname, st);
}

int fstat(int fd, struct stat *st)
{
    return _fstat(fd, st);
}

int ftruncate(int fd, off_t length)
{
    return ret_errno(sys_ftruncate(fd, (long)length));
}

int _ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

int truncate(const char *pathname, off_t length)
{
    return ret_errno(sys_truncate(pathname, (long)length));
}

int fsync(int fd)
{
    return ret_errno(sys_fsync(fd));
}

int _isatty(int fd)
{
    struct armos_termios tio;
    long ret = sys_ioctl(fd, TCGETS, &tio);

    if (ret >= 0)
        return 1;

    errno = (int)-ret;
    return 0;
}

time_t time(time_t *tloc)
{
    long ret = sys_time(NULL);

    if (ret < 0) {
        errno = (int)-ret;
        return (time_t)-1;
    }

    if (tloc)
        *tloc = (time_t)ret;
    return (time_t)ret;
}

int _gettimeofday(struct timeval *tv, void *tz)
{
    struct os_timeval otv;
    struct os_timezone otz;
    long ret;

    ret = sys_gettimeofday(tv ? (struct timeval *)&otv : NULL,
                           tz ? &otz : NULL);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }

    if (tv) {
        tv->tv_sec = (time_t)otv.tv_sec;
        tv->tv_usec = (suseconds_t)otv.tv_usec;
    }

    if (tz) {
        struct timezone *ntz = (struct timezone *)tz;
        ntz->tz_minuteswest = otz.tz_minuteswest;
        ntz->tz_dsttime = otz.tz_dsttime;
    }

    return 0;
}

int access(const char *pathname, int mode)
{
    return ret_errno(sys_access(pathname, mode));
}

void sync(void)
{
    (void)sys_sync();
}

int chdir(const char *path)
{
    return ret_errno(sys_chdir(path));
}

char *getcwd(char *buf, size_t size)
{
    long ret = sys_getcwd(buf, size);
    if (ret < 0) {
        errno = (int)-ret;
        return NULL;
    }
    return buf;
}

char *realpath(const char *path, char *resolved_path)
{
    char input[PATH_MAX];
    char normalized[PATH_MAX];
    char cwd[PATH_MAX];
    char *out = resolved_path;
    struct stat st;

    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }

    if (path[0] == '/') {
        if (strlen(path) >= sizeof(input)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
        strcpy(input, path);
    } else {
        if (!getcwd(cwd, sizeof(cwd)))
            return NULL;
        if (snprintf(input, sizeof(input), "%s/%s", cwd, path) >= (int)sizeof(input)) {
            errno = ENAMETOOLONG;
            return NULL;
        }
    }

    if (normalize_absolute_path(input, normalized, sizeof(normalized)) < 0) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    /*
     * Minimal POSIX realpath semantics for the ArmOS toolchain: the final path
     * must exist, and "." / ".." are collapsed. Symlink expansion can be added
     * later when a port needs it; TCC mostly uses this for #pragma once path
     * identity and accepts already-canonical absolute paths.
     */
    if (stat(normalized, &st) < 0)
        return NULL;

    if (!out) {
        out = malloc(PATH_MAX);
        if (!out) {
            errno = ENOMEM;
            return NULL;
        }
    }

    strcpy(out, normalized);
    return out;
}

void *_sbrk(ptrdiff_t incr)
{
    static char *heap_end;
    char *prev;
    long current;
    long next;

    if (!heap_end) {
        current = sys_brk(0);
        if (current < 0) {
            errno = (int)-current;
            return (void *)-1;
        }
        heap_end = (char *)current;
    }

    prev = heap_end;
    next = sys_brk((unsigned long)(heap_end + incr));
    if (next < 0) {
        errno = ENOMEM;
        return (void *)-1;
    }

    heap_end = (char *)next;
    return prev;
}

void _exit(int status)
{
    sys_exit(status);
    for (;;)
        ;
}

int _kill(int pid, int sig)
{
    return ret_errno(sys_kill(pid, signal_newlib_to_os(sig)));
}

pid_t _getpid(void)
{
    return (pid_t)sys_getpid();
}

pid_t getppid(void)
{
    return (pid_t)sys_getppid();
}

uid_t getuid(void)
{
    return (uid_t)sys_getuid();
}

uid_t geteuid(void)
{
    return (uid_t)sys_geteuid();
}

int setuid(uid_t uid)
{
    return ret_errno(sys_setuid((int)uid));
}

gid_t getgid(void)
{
    return (gid_t)sys_getgid();
}

gid_t getegid(void)
{
    return (gid_t)sys_getegid();
}

int setgid(gid_t gid)
{
    return ret_errno(sys_setgid((int)gid));
}

int getpriority(int which, id_t who)
{
    long ret = sys_getpriority(which, (int)who);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return 20 - (int)ret;
}

int setpriority(int which, id_t who, int prio)
{
    return ret_errno(sys_setpriority(which, (int)who, prio));
}

int nice(int inc)
{
    long ret = sys_nice(inc);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return getpriority(0, 0);
}

pid_t getpgrp(void)
{
    long ret = sys_getpgrp();
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    return (pid_t)ret;
}

int setpgid(pid_t pid, pid_t pgid)
{
    return ret_errno(sys_setpgid(pid, pgid));
}

pid_t setsid(void)
{
    long ret = sys_setsid();
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    return (pid_t)ret;
}

pid_t getsid(pid_t pid)
{
    long ret = sys_getsid(pid);
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    return (pid_t)ret;
}

int _fork(void)
{
    return ret_errno(sys_fork());
}

int _execve(const char *pathname, char *const argv[], char *const envp[])
{
    return ret_errno(sys_execve(pathname, argv, envp));
}

int _wait(int *status)
{
    long ret = sys_waitpid(-1, status, 0);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    if (status)
        *status = wait_status_os_to_newlib(*status);
    return (int)ret;
}

pid_t waitpid(pid_t pid, int *status, int options)
{
    long ret = sys_waitpid(pid, status, options);
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    if (status)
        *status = wait_status_os_to_newlib(*status);
    return (pid_t)ret;
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
    long ret = sys_wait4(pid, status, options, rusage);
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    if (status)
        *status = wait_status_os_to_newlib(*status);
    return (pid_t)ret;
}

int chmod(const char *path, mode_t mode)
{
    return ret_errno(sys_chmod(path, (int)mode));
}

int chown(const char *path, uid_t owner, gid_t group)
{
    int os_owner = ((unsigned int)owner == (unsigned int)(uid_t)-1) ? -1 : (int)owner;
    int os_group = ((unsigned int)group == (unsigned int)(gid_t)-1) ? -1 : (int)group;

    return ret_errno(sys_chown(path, os_owner, os_group));
}

mode_t umask(mode_t mask)
{
    long ret = sys_umask((int)mask);
    if (ret < 0) {
        errno = (int)-ret;
        return (mode_t)-1;
    }
    return (mode_t)ret;
}

int pipe(int pipefd[2])
{
    return ret_errno(sys_pipe(pipefd));
}

int dup(int oldfd)
{
    return ret_errno(sys_dup(oldfd));
}

int dup2(int oldfd, int newfd)
{
    return ret_errno(sys_dup2(oldfd, newfd));
}

int socket(int domain, int type, int protocol)
{
    return ret_errno(sys_socket(domain, type, protocol));
}

int bind(int sockfd, const void *addr, unsigned long addrlen)
{
    return ret_errno(sys_bind(sockfd, addr, addrlen));
}

int listen(int sockfd, int backlog)
{
    return ret_errno(sys_listen(sockfd, backlog));
}

int accept(int sockfd, void *addr, unsigned long *addrlen)
{
    return ret_errno(sys_accept(sockfd, addr, addrlen));
}

int connect(int sockfd, const void *addr, unsigned long addrlen)
{
    return ret_errno(sys_connect(sockfd, addr, addrlen));
}

int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    long arg = 0;

    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);

    return ret_errno(sys_fcntl(fd, cmd, arg));
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    void *arg;

    va_start(ap, request);
    arg = va_arg(ap, void *);
    va_end(ap);

    return ret_errno(sys_ioctl(fd, request, arg));
}

int tcgetattr(int fd, void *termios_p)
{
    return ioctl(fd, TCGETS, termios_p);
}

int tcsetattr(int fd, int optional_actions, const void *termios_p)
{
    int request = TCSETS;

    if (optional_actions == TCSANOW)
        request = TCSETS;
    else if (optional_actions == TCSADRAIN)
        request = TCSETSW;
    else if (optional_actions == TCSAFLUSH)
        request = TCSETSF;
    else {
        errno = EINVAL;
        return -1;
    }

    return ioctl(fd, request, termios_p);
}

int tcflush(int fd, int queue_selector)
{
    return ret_errno(sys_ioctl(fd, TCFLSH, (void *)queue_selector));
}

int tcdrain(int fd)
{
    struct armos_termios tio;

    if (tcgetattr(fd, &tio) < 0)
        return -1;

    return tcsetattr(fd, TCSADRAIN, &tio);
}

int tcsetpgrp(int fd, pid_t pgrp)
{
    return ret_errno(sys_stty(TTY_STTY_SET_FOREGROUND_PGID_FD, fd, pgrp));
}

pid_t tcgetpgrp(int fd)
{
    long ret;

    ret = sys_gtty(TTY_GTTY_GET_FOREGROUND_PGID_FD, fd);
    if (ret < 0) {
        errno = (int)-ret;
        return (pid_t)-1;
    }
    return (pid_t)ret;
}

int getdents(int fd, void *dirp, size_t count)
{
    return ret_errno(sys_getdents(fd, dirp, count));
}

DIR *opendir(const char *name)
{
    DIR *dir;
    int fd;

    if (!name) {
        errno = EINVAL;
        return NULL;
    }

    fd = open(name, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return NULL;

    dir = calloc(1, sizeof(*dir));
    if (!dir) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }

    dir->fd = fd;
    return dir;
}

struct dirent *readdir(DIR *dirp)
{
    struct linux_dirent *raw;
    size_t name_len;

    if (!dirp) {
        errno = EBADF;
        return NULL;
    }

    for (;;) {
        if (dirp->pos >= dirp->len) {
            int n = getdents(dirp->fd, dirp->buffer, sizeof(dirp->buffer));
            if (n <= 0)
                return NULL;
            dirp->pos = 0;
            dirp->len = (size_t)n;
        }

        raw = (struct linux_dirent *)(dirp->buffer + dirp->pos);
        if (raw->d_reclen == 0 || dirp->pos + raw->d_reclen > dirp->len) {
            errno = EIO;
            return NULL;
        }
        dirp->pos += raw->d_reclen;

        dirp->current.d_ino = raw->d_ino;
        dirp->current.d_off = raw->d_off;
        dirp->current.d_reclen = raw->d_reclen;
        dirp->current.d_type = raw->d_type;
        name_len = strnlen(raw->d_name, NAME_MAX);
        memcpy(dirp->current.d_name, raw->d_name, name_len);
        dirp->current.d_name[name_len] = '\0';
        return &dirp->current;
    }
}

void rewinddir(DIR *dirp)
{
    if (!dirp)
        return;
    lseek(dirp->fd, 0, SEEK_SET);
    dirp->pos = 0;
    dirp->len = 0;
}

int closedir(DIR *dirp)
{
    int ret;

    if (!dirp) {
        errno = EBADF;
        return -1;
    }

    ret = close(dirp->fd);
    free(dirp);
    return ret;
}

int dirfd(DIR *dirp)
{
    if (!dirp) {
        errno = EBADF;
        return -1;
    }
    return dirp->fd;
}

int getsysinfo(void *resp)
{
    return ret_errno(sys_sysinfo(resp));
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    return ret_errno(sys_nanosleep(req, rem));
}

int usleep(useconds_t usec)
{
    struct timespec req;

    req.tv_sec = usec / 1000000U;
    req.tv_nsec = (long)(usec % 1000000U) * 1000L;
    return nanosleep(&req, NULL);
}

unsigned int sleep(unsigned int seconds)
{
    struct timespec req;
    struct timespec rem;

    req.tv_sec = (time_t)seconds;
    req.tv_nsec = 0;

    while (nanosleep(&req, &rem) < 0) {
        if (errno != EINTR)
            return (unsigned int)req.tv_sec;

        if (rem.tv_sec == 0 && rem.tv_nsec == 0)
            return 0;

        req = rem;
    }

    return 0;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *oldact)
{
    struct os_sigaction os_act;
    struct os_sigaction os_old;
    long ret;

    ret = sys_sigaction(signal_newlib_to_os(sig),
                        act ? (void *)&(struct os_sigaction) {
                            .sa_handler = act->sa_handler,
                            .sa_mask = (uint32_t)act->sa_mask,
                            .sa_flags = act->sa_flags,
                            .sa_restorer = __signal_return_trampoline,
                        } : NULL,
                        oldact ? &os_old : NULL);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }

    if (oldact) {
        oldact->sa_handler = os_old.sa_handler;
        oldact->sa_mask = (sigset_t)os_old.sa_mask;
        oldact->sa_flags = os_old.sa_flags;
    }

    (void)os_act;
    return 0;
}

#ifdef sigemptyset
#undef sigemptyset
#endif
#ifdef sigfillset
#undef sigfillset
#endif
#ifdef sigaddset
#undef sigaddset
#endif
#ifdef sigdelset
#undef sigdelset
#endif
#ifdef sigismember
#undef sigismember
#endif

int sigemptyset(sigset_t *set)
{
    if (!set) {
        errno = EFAULT;
        return -1;
    }
    *set = 0;
    return 0;
}

int sigfillset(sigset_t *set)
{
    if (!set) {
        errno = EFAULT;
        return -1;
    }
    *set = ~(sigset_t)0;
    return 0;
}

int sigaddset(sigset_t *set, const int sig)
{
    if (!set) {
        errno = EFAULT;
        return -1;
    }
    if (sig <= 0 || sig >= 32) {
        errno = EINVAL;
        return -1;
    }
    *set |= (sigset_t)(1u << sig);
    return 0;
}

int sigdelset(sigset_t *set, const int sig)
{
    if (!set) {
        errno = EFAULT;
        return -1;
    }
    if (sig <= 0 || sig >= 32) {
        errno = EINVAL;
        return -1;
    }
    *set &= ~(sigset_t)(1u << sig);
    return 0;
}

int sigismember(const sigset_t *set, int sig)
{
    if (!set) {
        errno = EFAULT;
        return -1;
    }
    if (sig <= 0 || sig >= 32) {
        errno = EINVAL;
        return -1;
    }
    return ((*set & (sigset_t)(1u << sig)) != 0);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    uint32_t os_set;
    uint32_t os_old;
    long ret;

    os_set = set ? sigset_newlib_to_os(*set) : 0;
    ret = sys_sigprocmask(how, set ? &os_set : NULL, oldset ? &os_old : NULL);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    if (oldset)
        *oldset = sigset_os_to_newlib(os_old);
    return 0;
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
    return sigprocmask(how, set, oldset);
}

int sigpending(sigset_t *set)
{
    uint32_t os_set;
    long ret;

    if (!set) {
        errno = EFAULT;
        return -1;
    }
    ret = sys_sigpending(&os_set);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    *set = sigset_os_to_newlib(os_set);
    return 0;
}

int sigsuspend(const sigset_t *mask)
{
    uint32_t os_mask;
    long ret;

    if (!mask) {
        errno = EFAULT;
        return -1;
    }
    os_mask = sigset_newlib_to_os(*mask);
    ret = sys_sigsuspend(&os_mask);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return ret_errno(ret);
}

_sig_func_ptr _signal_r(struct _reent *r, int sig, _sig_func_ptr handler)
{
    struct sigaction act;
    struct sigaction oldact;

    (void)r;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handler;
    act.sa_flags = 1; /* arm-os SA_RESTART */

    if (sigaction(sig, &act, &oldact) < 0)
        return SIG_ERR;

    return oldact.sa_handler;
}

_sig_func_ptr signal(int sig, _sig_func_ptr handler)
{
    return _signal_r(NULL, sig, handler);
}

int shm_open(const char *name, size_t size, int flags)
{
    return ret_errno(sys_shm_open(name, size, flags));
}

int shm_unlink(const char *name)
{
    return ret_errno(sys_shm_unlink(name));
}

void *shm_map(int id, void *addr, int flags)
{
    long ret = sys_shm_map(id, addr, flags);
    if (ret < 0) {
        errno = (int)-ret;
        return NULL;
    }
    return (void *)ret;
}

int shm_unmap(void *addr, size_t size)
{
    return ret_errno(sys_shm_unmap(addr, size));
}

clock_t _times(struct tms *buf)
{
    long ret = sys_times(buf);
    if (ret < 0) {
        errno = (int)-ret;
        return (clock_t)-1;
    }
    return (clock_t)ret;
}

clock_t times(struct tms *buf)
{
    return _times(buf);
}

unsigned int alarm(unsigned int seconds)
{
    long ret = sys_alarm(seconds);
    if (ret < 0) {
        errno = (int)-ret;
        return 0;
    }
    return (unsigned int)ret;
}

int pause(void)
{
    return ret_errno(sys_pause());
}

int utime(const char *pathname, const struct utimbuf *times)
{
    return ret_errno(sys_utime(pathname, times));
}

int mknod(const char *pathname, mode_t mode, unsigned long dev)
{
    return ret_errno(sys_mknod(pathname, (int)mode, dev));
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout)
{
    return ret_errno(sys_select(nfds, readfds, writefds, exceptfds, timeout));
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return ret_errno(sys_poll(fds, nfds, timeout));
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds,
            fd_set *exceptfds, const struct timespec *timeout,
            const sigset_t *sigmask)
{
    struct timeval tv;
    sigset_t oldmask;
    sigset_t tmpmask;
    int ret;

    /*
     * ArmOS currently implements pselect in userland glue. That is enough for
     * portable software expecting the symbol, but unlike Linux it is not an
     * atomic mask+wait transition yet.
     */
    if (sigmask && sigprocmask(SIG_SETMASK, sigmask, &oldmask) < 0)
        return -1;

    if (timeout) {
        if (timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            if (sigmask)
                sigprocmask(SIG_SETMASK, &oldmask, NULL);
            errno = EINVAL;
            return -1;
        }
        tv.tv_sec = timeout->tv_sec;
        tv.tv_usec = timeout->tv_nsec / 1000L;
    }

    ret = select(nfds, readfds, writefds, exceptfds, timeout ? &tv : NULL);
    if (sigmask) {
        tmpmask = oldmask;
        sigprocmask(SIG_SETMASK, &tmpmask, NULL);
    }
    return ret;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout,
          const sigset_t *sigmask)
{
    sigset_t oldmask;
    sigset_t tmpmask;
    int timeout_ms = -1;
    int ret;

    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
            timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        timeout_ms = (int)(timeout->tv_sec * 1000L +
                           (timeout->tv_nsec + 999999L) / 1000000L);
    }

    if (sigmask && sigprocmask(SIG_SETMASK, sigmask, &oldmask) < 0)
        return -1;
    ret = poll(fds, nfds, timeout_ms);
    if (sigmask) {
        tmpmask = oldmask;
        sigprocmask(SIG_SETMASK, &tmpmask, NULL);
    }
    return ret;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    long ret = sys_readv(fd, iov, iovcnt);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return (ssize_t)ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    long ret = sys_writev(fd, iov, iovcnt);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return (ssize_t)ret;
}

int getrusage(int who, struct rusage *usage)
{
    return ret_errno(sys_getrusage(who, usage));
}

int getrlimit(int resource, struct rlimit *rlim)
{
    if (!rlim) {
        errno = EFAULT;
        return -1;
    }

    switch (resource) {
    case RLIMIT_NOFILE:
        rlim->rlim_cur = ARMOS_OPEN_MAX;
        rlim->rlim_max = ARMOS_OPEN_MAX;
        return 0;
    case RLIMIT_STACK:
    case RLIMIT_DATA:
    case RLIMIT_AS:
    case RLIMIT_RSS:
    case RLIMIT_CORE:
    case RLIMIT_CPU:
    case RLIMIT_FSIZE:
        rlim->rlim_cur = RLIM_INFINITY;
        rlim->rlim_max = RLIM_INFINITY;
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

int setrlimit(int resource, const struct rlimit *rlim)
{
    if (!rlim) {
        errno = EFAULT;
        return -1;
    }

    if (resource != RLIMIT_NOFILE) {
        errno = EINVAL;
        return -1;
    }

    if (rlim->rlim_cur > ARMOS_OPEN_MAX || rlim->rlim_max > ARMOS_OPEN_MAX) {
        errno = EPERM;
        return -1;
    }

    return 0;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    long ret;

    if (offset != 0) {
        errno = ENOSYS;
        return (void *)-1;
    }

    ret = sys_mmap(addr, length, prot, flags, fd);
    if (ret < 0) {
        errno = (int)-ret;
        return (void *)-1;
    }
    return (void *)ret;
}

int munmap(void *addr, size_t length)
{
    return ret_errno(sys_munmap(addr, length));
}

int mprotect(void *addr, size_t length, int prot)
{
    return ret_errno(sys_mprotect(addr, length, prot));
}

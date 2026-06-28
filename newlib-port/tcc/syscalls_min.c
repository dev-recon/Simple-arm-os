/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: newlib-port/tcc/syscalls_min.c
 * Layer: Userland / TinyCC bring-up
 *
 * Responsibilities:
 * - Provide the smallest newlib syscall surface needed to link a TinyCC-built
 *   ArmOS hello-world binary.
 * - Avoid high-level POSIX wrappers already provided by newlib, so TCC's
 *   stricter linker does not hit duplicate symbols such as signal/_signal_r.
 *
 * Notes:
 * - This file is experimental and intentionally separate from the stable
 *   newlib-port/syscalls.c used by normal ArmOS userland builds.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>

extern long sys_read(int fd, void *buf, unsigned long count);
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_open(const char *pathname, int flags, int mode);
extern long sys_close(int fd);
extern long sys_link(const char *oldpath, const char *newpath);
extern long sys_unlink(const char *pathname);
extern long sys_lseek(int fd, long offset, int whence);
extern long sys_stat(const char *pathname, void *st);
extern long sys_fstat(int fd, void *st);
extern long sys_brk(unsigned long brk);
extern long sys_getpid(void);
extern long sys_kill(int pid, int sig);
extern void sys_exit(int status);

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

static int ret_errno(long ret)
{
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    return (int)ret;
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

int _close(int fd)
{
    return ret_errno(sys_close(fd));
}

int _unlink(const char *pathname)
{
    return ret_errno(sys_unlink(pathname));
}

int _link(const char *oldpath, const char *newpath)
{
    return ret_errno(sys_link(oldpath, newpath));
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

int _isatty(int fd)
{
    struct stat st;
    if (_fstat(fd, &st) < 0)
        return 0;
    return S_ISCHR(st.st_mode) ? 1 : 0;
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
    return ret_errno(sys_kill(pid, sig));
}

pid_t _getpid(void)
{
    return (pid_t)sys_getpid();
}

clock_t _times(struct tms *buf)
{
    if (buf)
        memset(buf, 0, sizeof(*buf));
    return 0;
}

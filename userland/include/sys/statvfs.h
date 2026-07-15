/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/statvfs.h
 * Layer: Userland / POSIX public interface
 *
 * Responsibilities:
 * - Expose POSIX filesystem capacity and capability statistics.
 * - Use newlib's filesystem counter types on both supported ABIs.
 *
 * Notes:
 * - ArmOS filesystems are currently mounted read-write without per-mount
 *   ST_NOSUID semantics, so f_flag is zero for the supported mounts.
 */

#ifndef _SYS_STATVFS_H
#define _SYS_STATVFS_H

#include <sys/types.h>

#define ST_RDONLY 0x0001ul
#define ST_NOSUID 0x0002ul

struct statvfs {
    unsigned long f_bsize;
    unsigned long f_frsize;
    fsblkcnt_t f_blocks;
    fsblkcnt_t f_bfree;
    fsblkcnt_t f_bavail;
    fsfilcnt_t f_files;
    fsfilcnt_t f_ffree;
    fsfilcnt_t f_favail;
    unsigned long f_fsid;
    unsigned long f_flag;
    unsigned long f_namemax;
};

#ifdef __cplusplus
extern "C" {
#endif

int statvfs(const char *path, struct statvfs *buf);
int fstatvfs(int fd, struct statvfs *buf);

#ifdef __cplusplus
}
#endif

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/uapi/armos/statvfs.h
 * Layer: UAPI / filesystem statistics ABI
 *
 * Responsibilities:
 * - Define architecture-neutral filesystem statistics exchanged with userland.
 * - Keep block and inode counters stable across the ARM32 and ARM64 ABIs.
 *
 * Notes:
 * - Public libc structures are populated by the newlib adaptation layer.
 */

#ifndef _UAPI_ARMOS_STATVFS_H
#define _UAPI_ARMOS_STATVFS_H

typedef struct {
    unsigned long long f_bsize;
    unsigned long long f_frsize;
    unsigned long long f_blocks;
    unsigned long long f_bfree;
    unsigned long long f_bavail;
    unsigned long long f_files;
    unsigned long long f_ffree;
    unsigned long long f_favail;
    unsigned long long f_fsid;
    unsigned long long f_flag;
    unsigned long long f_namemax;
} armos_statvfs_t;

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/dirent.h
 * Layer: Userland / public header
 * Description: Userspace ABI or library declarations for ArmOS programs.
 */

#ifndef ARM_OS_NEWLIB_DIRENT_H
#define ARM_OS_NEWLIB_DIRENT_H

#include <stdint.h>
#include <sys/types.h>

struct linux_dirent {
    uint32_t d_ino;
    uint32_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12
#define DT_WHT     14

int getdents(int fd, void *dirp, size_t count);

#endif


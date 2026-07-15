/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/stat.h
 * Layer: Userland / POSIX compatibility
 * Description: Newlib stat wrapper exposing ArmOS filesystem extensions.
 */

#ifndef ARMOS_SYS_STAT_H
#define ARMOS_SYS_STAT_H

#include_next <sys/stat.h>

#ifndef UTIME_NOW
#define UTIME_NOW  (-2L)
#endif
#ifndef UTIME_OMIT
#define UTIME_OMIT (-1L)
#endif

int lstat(const char *path, struct stat *buf);
int mknod(const char *path, mode_t mode, unsigned long dev);

#endif /* ARMOS_SYS_STAT_H */

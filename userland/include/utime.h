/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/utime.h
 * Layer: Userland / C library compatibility
 * Description: POSIX utime(2) declaration.
 */

#ifndef _ARMOS_UTIME_H
#define _ARMOS_UTIME_H

#include <time.h>

struct utimbuf {
    time_t actime;
    time_t modtime;
};

int utime(const char *filename, const struct utimbuf *times);

#endif /* _ARMOS_UTIME_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/time.h
 * Layer: Userland / POSIX compatibility
 *
 * Responsibilities:
 * - Extend newlib's time interface with the POSIX clocks implemented by ArmOS.
 * - Expose one architecture-independent contract to native programs and ports.
 *
 * Notes:
 * - Newlib only exposes its POSIX timer declarations for selected targets.
 *   ArmOS implements realtime and monotonic clocks without POSIX timer objects.
 */

#ifndef ARMOS_TIME_H
#define ARMOS_TIME_H

#include_next <time.h>

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC ((clockid_t)4)
#endif

#ifdef __cplusplus
extern "C" {
#endif

int clock_gettime(clockid_t clock_id, struct timespec *tp);
int clock_getres(clockid_t clock_id, struct timespec *res);
int clock_nanosleep(clockid_t clock_id, int flags,
                    const struct timespec *req, struct timespec *rem);
int nanosleep(const struct timespec *req, struct timespec *rem);

#ifdef __cplusplus
}
#endif

#endif /* ARMOS_TIME_H */

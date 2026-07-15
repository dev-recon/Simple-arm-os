/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/uapi/armos/resource.h
 * Layer: UAPI / process resource limits
 *
 * Responsibilities:
 * - Define architecture-neutral resource-limit values exchanged with userland.
 * - Keep limit widths stable across the ARM32 and ARM64 ABIs.
 *
 * Notes:
 * - Public libc structures are populated by the newlib adaptation layer.
 */

#ifndef _UAPI_ARMOS_RESOURCE_H
#define _UAPI_ARMOS_RESOURCE_H

#define ARMOS_RLIMIT_CPU     0
#define ARMOS_RLIMIT_FSIZE   1
#define ARMOS_RLIMIT_DATA    2
#define ARMOS_RLIMIT_STACK   3
#define ARMOS_RLIMIT_CORE    4
#define ARMOS_RLIMIT_RSS     5
#define ARMOS_RLIMIT_NOFILE  7
#define ARMOS_RLIMIT_AS      9

#define ARMOS_RLIM_INFINITY (~0ULL)

typedef struct {
    unsigned long long current;
    unsigned long long maximum;
} armos_rlimit_t;

#endif

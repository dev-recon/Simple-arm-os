/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/uapi/armos/syscall.h
 * Layer: UAPI / syscall ABI
 *
 * Responsibilities:
 * - Define syscall numbers shared by kernel and architecture entry paths.
 * - Preserve the Linux ARM32-compatible number space used by ArmOS userland.
 *
 * Notes:
 * - Each architecture defines its own register calling convention.
 * - sched_yield uses the established Linux-compatible syscall slot 158.
 */

#ifndef _UAPI_ARMOS_SYSCALL_H
#define _UAPI_ARMOS_SYSCALL_H

#define ARMOS_NR_EXIT       1
#define ARMOS_NR_WRITE      4
#define ARMOS_NR_SCHED_YIELD 158
#define ARMOS_SYSCALL_MAX 512

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/syscall_dispatch.h
 * Layer: Kernel / generic syscall dispatch
 *
 * Responsibilities:
 * - Describe an architecture-neutral six-argument syscall request.
 * - Preserve native register width for ARM32 and ARM64 callers.
 *
 * Notes:
 * - Architecture exception entry only decodes registers into this request.
 * - The common syscall layer owns all dispatch and subsystem policy.
 */

#ifndef _KERNEL_SYSCALL_DISPATCH_H
#define _KERNEL_SYSCALL_DISPATCH_H

#include <kernel/types.h>
#include <uapi/armos/syscall.h>

#define ARMOS_SYSCALL_ARGUMENT_COUNT 6u

typedef uintptr_t syscall_word_t;
typedef intptr_t syscall_result_t;

typedef struct syscall_request {
    uint32_t number;
    syscall_word_t arguments[ARMOS_SYSCALL_ARGUMENT_COUNT];
} syscall_request_t;

#endif /* _KERNEL_SYSCALL_DISPATCH_H */

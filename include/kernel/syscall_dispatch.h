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
 * - Own the complete ArmOS syscall-number table independently of VFS policy.
 * - Preserve native register width for ARM32 and ARM64 callers.
 *
 * Notes:
 * - Subsystems register handlers as they become available on a target.
 * - An unregistered valid syscall number returns ENOSYS.
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

typedef syscall_result_t (*syscall_dispatch_handler_t)(
    void *owner, const syscall_request_t *request);

typedef struct syscall_dispatcher {
    syscall_dispatch_handler_t handlers[ARMOS_SYSCALL_MAX];
    void *owners[ARMOS_SYSCALL_MAX];
    syscall_dispatch_handler_t fallback;
    void *fallback_owner;
    uint64_t calls;
    uint64_t rejected;
} syscall_dispatcher_t;

void syscall_dispatcher_init(syscall_dispatcher_t *dispatcher);
int syscall_dispatcher_register(syscall_dispatcher_t *dispatcher,
                                uint32_t number,
                                syscall_dispatch_handler_t handler,
                                void *owner);
int syscall_dispatcher_bind(syscall_dispatcher_t *dispatcher,
                            uint32_t number,
                            syscall_dispatch_handler_t handler,
                            void *owner);
int syscall_dispatcher_set_fallback(syscall_dispatcher_t *dispatcher,
                                    syscall_dispatch_handler_t handler,
                                    void *owner);
syscall_result_t syscall_dispatcher_dispatch(
    syscall_dispatcher_t *dispatcher,
    const syscall_request_t *request);

#endif /* _KERNEL_SYSCALL_DISPATCH_H */

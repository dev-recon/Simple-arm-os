/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/exception.h
 * Layer: ARM64 / exception interface
 *
 * Responsibilities:
 * - Register the active generic EL0 VM identity and saved register context.
 * - Attach an optional task dispatcher to syscall and IRQ-return handling.
 * - Expose syscall smoke-test results to the platform bring-up code.
 *
 * Notes:
 * - The legacy direct EL0 probe remains supported when no dispatcher is set.
 */

#ifndef ARMOS_ARM64_EXCEPTION_H
#define ARMOS_ARM64_EXCEPTION_H

#include <asm/user_context.h>
#include <kernel/memory.h>

struct task_dispatcher;

typedef unsigned long long arm64_exception_u64;

void arm64_exception_set_el0_context(const vm_space_t *vm_space,
                                     arm64_user_context_t *registers,
                                     arm64_exception_u64 exit_address);
void arm64_exception_set_task_dispatcher(
    struct task_dispatcher *dispatcher);
unsigned int arm64_exception_el0_syscall_count(void);
arm64_exception_u64 arm64_exception_el0_exit_status(void);

#endif

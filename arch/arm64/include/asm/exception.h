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
 * - Attach an optional timer-tick hook for scheduler wakeup policy.
 * - Commit a prepared exec image atomically at the syscall return boundary.
 * - Expose syscall smoke-test results to the platform bring-up code.
 *
 * Notes:
 * - The legacy direct EL0 probe remains supported when no dispatcher is set.
 */

#ifndef ARMOS_ARM64_EXCEPTION_H
#define ARMOS_ARM64_EXCEPTION_H

#include <asm/user_context.h>
#include <kernel/memory.h>
#include <kernel/syscall_dispatch.h>

struct task_dispatcher;

typedef unsigned long long arm64_exception_u64;
typedef int (*arm64_timer_tick_hook_t)(unsigned int ticks);
typedef int (*arm64_page_fault_hook_t)(vaddr_t address, int is_write,
                                       int is_execute);
typedef void (*arm64_exec_commit_hook_t)(const vm_space_t *previous_vm,
                                         void *owner);

void arm64_exception_set_el0_context(const vm_space_t *vm_space,
                                     arm64_user_context_t *registers,
                                     arm64_exception_u64 exit_address);
int arm64_exception_request_exec(const vm_space_t *vm_space,
                                 arm64_user_context_t *registers,
                                 arm64_exec_commit_hook_t commit_hook,
                                 void *commit_owner);
void arm64_exception_set_task_dispatcher(
    struct task_dispatcher *dispatcher);
void arm64_exception_set_syscall_dispatcher(
    syscall_dispatcher_t *dispatcher);
void arm64_exception_set_timer_tick_hook(arm64_timer_tick_hook_t hook);
void arm64_exception_set_page_fault_hook(arm64_page_fault_hook_t hook);
unsigned int arm64_exception_el0_syscall_count(void);
arm64_exception_u64 arm64_exception_el0_exit_status(void);

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_task.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose the architecture task-context type to generic scheduler code.
 * - Keep register layout details in the active architecture tree.
 *
 * Notes:
 * - task_context_t is intentionally opaque to portable kernel code at the
 *   design level, even though existing code still accesses fields directly.
 *   Those call sites are the next cleanup target.
 */

#ifndef _KERNEL_ARCH_TASK_H
#define _KERNEL_ARCH_TASK_H

#include <asm/task_context.h>

#define ARCH_TASK_KERNEL_CPSR          0x13u
#define ARCH_TASK_STACK_ALIGNMENT      8u
#define ARCH_TASK_KERNEL_STACK_RESERVE 512u

static inline vaddr_t arch_task_stack_align(vaddr_t sp)
{
    return sp & ~(vaddr_t)(ARCH_TASK_STACK_ALIGNMENT - 1u);
}

static inline void arch_task_context_set_kernel_stack(task_context_t *ctx,
                                                      vaddr_t stack_top,
                                                      vaddr_t sp)
{
    ctx->svc_sp_top = (uint32_t)stack_top;
    ctx->svc_sp = (uint32_t)arch_task_stack_align(sp);
    ctx->sp = ctx->svc_sp;
}

static inline void arch_task_context_prepare_kernel_stack(task_context_t *ctx,
                                                         vaddr_t stack_top)
{
    arch_task_context_set_kernel_stack(
        ctx,
        stack_top,
        stack_top - ARCH_TASK_KERNEL_STACK_RESERVE);
}

static inline void arch_task_context_set_returns_to_user(task_context_t *ctx,
                                                        bool returns_to_user)
{
    ctx->returns_to_user = returns_to_user ? 1u : 0u;
}

static inline void arch_task_context_init_kernel_entry(task_context_t *ctx,
                                                       void (*entry)(void *),
                                                       void *arg,
                                                       vaddr_t stack_top)
{
    ctx->r0 = (uint32_t)(uintptr_t)arg;
    arch_task_context_prepare_kernel_stack(ctx, stack_top);
    ctx->lr = 0;
    ctx->pc = (uint32_t)(uintptr_t)entry;
    ctx->cpsr = ARCH_TASK_KERNEL_CPSR;
    ctx->is_first_run = 1;
    arch_task_context_set_returns_to_user(ctx, false);
}

#endif /* _KERNEL_ARCH_TASK_H */

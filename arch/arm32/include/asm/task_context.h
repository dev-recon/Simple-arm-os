/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/task_context.h
 * Layer: ARM32 / scheduler context ABI
 *
 * Responsibilities:
 * - Define the ARM32 task context consumed by task_switch.S, syscall.S, and
 *   IRQ return code.
 * - Keep the exact C layout available to asm-offsets generation.
 *
 * Notes:
 * - Field order is ABI. Do not edit without rebuilding asm offsets and auditing
 *   the ARM assembly paths that consume CTX_* symbols.
 */

#ifndef _ASM_TASK_CONTEXT_H
#define _ASM_TASK_CONTEXT_H

#include <kernel/types.h>

typedef struct task_context {
    /* Kernel-mode saved registers r0-r12. */
    uint32_t r0, r1, r2, r3, r4, r5, r6;
    uint32_t r7, r8, r9, r10, r11, r12;

    /* Kernel-mode control state. */
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t cpsr;

    uint32_t is_first_run;
    uint32_t ttbr0;
    uint32_t asid;

    uint32_t spsr;
    uint32_t returns_to_user;

    /*
     * User-mode image captured on SVC/IRQ entry, or prepared by exec/signal
     * delivery before returning to user mode.
     */
    uint32_t usr_r[13];
    uint32_t usr_sp;
    uint32_t usr_lr;
    uint32_t usr_pc;
    uint32_t usr_cpsr;

    /* SVC stack bookkeeping used by ARM32 context switch and diagnostics. */
    uint32_t svc_sp_top;
    uint32_t svc_sp;
    uint32_t svc_lr_saved;
} __attribute__((aligned(8))) task_context_t;

#define ARCH_TASK_KERNEL_CPSR          0x13u
#define ARCH_TASK_USER_CPSR            0x60000010u
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

static inline void arch_task_context_mark_first_run(task_context_t *ctx)
{
    ctx->is_first_run = 1u;
}

static inline void arch_task_context_set_address_space(task_context_t *ctx,
                                                       uintptr_t address_space,
                                                       uint32_t asid)
{
    ctx->ttbr0 = (uint32_t)address_space;
    ctx->asid = asid;
}

static inline void arch_task_context_set_user_register(task_context_t *ctx,
                                                       uint32_t reg,
                                                       uint32_t value)
{
    if (reg < 13u)
        ctx->usr_r[reg] = value;
}

static inline void arch_task_context_init_user_entry(task_context_t *ctx,
                                                     uintptr_t address_space,
                                                     uint32_t asid,
                                                     vaddr_t kernel_stack_top,
                                                     vaddr_t user_pc,
                                                     vaddr_t user_sp)
{
    arch_task_context_mark_first_run(ctx);
    arch_task_context_set_address_space(ctx, address_space, asid);
    arch_task_context_set_returns_to_user(ctx, true);
    ctx->cpsr = ARCH_TASK_USER_CPSR;
    arch_task_context_prepare_kernel_stack(ctx, kernel_stack_top);
    ctx->usr_pc = (uint32_t)user_pc;
    ctx->usr_sp = (uint32_t)user_sp;
    ctx->usr_cpsr = ARCH_TASK_USER_CPSR;
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
    arch_task_context_mark_first_run(ctx);
    arch_task_context_set_returns_to_user(ctx, false);
}

#endif /* _ASM_TASK_CONTEXT_H */

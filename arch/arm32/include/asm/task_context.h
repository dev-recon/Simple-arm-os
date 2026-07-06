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

typedef struct arch_task_user_context {
    uint32_t r[13];
    vaddr_t sp;
    vaddr_t lr;
    vaddr_t pc;
    uint32_t cpsr;
} arch_task_user_context_t;

#define ARCH_TASK_KERNEL_CPSR          0x13u
#define ARCH_TASK_USER_CPSR            0x60000010u
#define ARCH_TASK_STACK_ALIGNMENT      8u
#define ARCH_TASK_KERNEL_STACK_RESERVE 512u

static inline vaddr_t arch_task_stack_align(vaddr_t sp)
{
    return sp & ~(vaddr_t)(ARCH_TASK_STACK_ALIGNMENT - 1u);
}

static inline vaddr_t arch_task_context_kernel_sp(const task_context_t *ctx)
{
    return (vaddr_t)ctx->sp;
}

static inline vaddr_t arch_task_context_svc_sp(const task_context_t *ctx)
{
    return (vaddr_t)ctx->svc_sp;
}

static inline void arch_task_context_set_kernel_sp(task_context_t *ctx,
                                                   vaddr_t sp)
{
    ctx->sp = (uint32_t)arch_task_stack_align(sp);
}

static inline void arch_task_context_set_svc_sp(task_context_t *ctx,
                                                vaddr_t sp)
{
    ctx->svc_sp = (uint32_t)arch_task_stack_align(sp);
}

static inline void arch_task_context_save_kernel_sp(task_context_t *ctx,
                                                    vaddr_t sp)
{
    ctx->sp = (uint32_t)sp;
    ctx->svc_sp = (uint32_t)sp;
}

static inline vaddr_t arch_task_context_kernel_lr(const task_context_t *ctx)
{
    return (vaddr_t)ctx->lr;
}

static inline vaddr_t arch_task_context_kernel_pc(const task_context_t *ctx)
{
    return (vaddr_t)ctx->pc;
}

static inline void arch_task_context_set_kernel_lr(task_context_t *ctx,
                                                   vaddr_t lr)
{
    ctx->lr = (uint32_t)lr;
}

static inline void arch_task_context_set_kernel_pc(task_context_t *ctx,
                                                   vaddr_t pc)
{
    ctx->pc = (uint32_t)pc;
}

static inline void arch_task_context_set_kernel_return_value(task_context_t *ctx,
                                                            uint32_t value)
{
    ctx->r0 = value;
}

static inline void arch_task_context_set_kernel_stack(task_context_t *ctx,
                                                      vaddr_t stack_top,
                                                      vaddr_t sp)
{
    ctx->svc_sp_top = (uint32_t)stack_top;
    arch_task_context_set_svc_sp(ctx, sp);
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

static inline uint32_t arch_task_context_user_cpsr(uint32_t cpsr)
{
    return (cpsr & ~0x1fu) | 0x10u;
}

static inline void arch_task_context_set_user_register(task_context_t *ctx,
                                                       uint32_t reg,
                                                       uint32_t value)
{
    if (reg < 13u)
        ctx->usr_r[reg] = value;
}

static inline vaddr_t arch_task_context_user_sp(const task_context_t *ctx)
{
    return (vaddr_t)ctx->usr_sp;
}

static inline void arch_task_context_capture_user(const task_context_t *ctx,
                                                  arch_task_user_context_t *user)
{
    uint32_t i;

    for (i = 0; i < 13u; i++)
        user->r[i] = ctx->usr_r[i];
    user->sp = (vaddr_t)ctx->usr_sp;
    user->lr = (vaddr_t)ctx->usr_lr;
    user->pc = (vaddr_t)ctx->usr_pc;
    user->cpsr = ctx->usr_cpsr;
}

static inline void arch_task_context_restore_user(task_context_t *ctx,
                                                  const arch_task_user_context_t *user)
{
    uint32_t i;

    for (i = 0; i < 13u; i++)
        ctx->usr_r[i] = user->r[i];
    ctx->usr_sp = (uint32_t)user->sp;
    ctx->usr_lr = (uint32_t)user->lr;
    ctx->usr_pc = (uint32_t)user->pc;
    ctx->usr_cpsr = arch_task_context_user_cpsr(user->cpsr);
    arch_task_context_set_returns_to_user(ctx, true);
}

static inline void arch_task_context_enter_signal_handler(task_context_t *ctx,
                                                          uint32_t sig,
                                                          vaddr_t handler,
                                                          vaddr_t restorer,
                                                          vaddr_t frame_sp,
                                                          uint32_t saved_cpsr)
{
    arch_task_context_set_user_register(ctx, 0, sig);
    ctx->usr_sp = (uint32_t)frame_sp;
    ctx->usr_lr = (uint32_t)restorer;
    ctx->usr_pc = (uint32_t)handler;
    ctx->usr_cpsr = arch_task_context_user_cpsr(saved_cpsr);
    arch_task_context_set_returns_to_user(ctx, true);
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

static inline void arch_task_context_prepare_user_fork(task_context_t *child,
                                                       const task_context_t *parent,
                                                       uintptr_t address_space,
                                                       uint32_t asid,
                                                       vaddr_t kernel_return_pc,
                                                       uint32_t saved_status)
{
    arch_task_user_context_t user;

    arch_task_context_set_address_space(child, address_space, asid);
    arch_task_context_capture_user(parent, &user);
    user.cpsr = saved_status;
    arch_task_context_restore_user(child, &user);
    arch_task_context_set_user_register(child, 0, 0);

    child->r0 = 0;
    child->lr = (uint32_t)kernel_return_pc;
    child->pc = (uint32_t)kernel_return_pc;
    child->spsr = saved_status;
    arch_task_context_mark_first_run(child);
}

static inline void arch_task_context_prepare_kernel_fork(task_context_t *child,
                                                         const task_context_t *parent,
                                                         uintptr_t address_space,
                                                         uint32_t asid,
                                                         vaddr_t kernel_return_pc,
                                                         uint32_t saved_status)
{
    (void)parent;
    arch_task_context_set_address_space(child, address_space, asid);
    arch_task_context_set_user_register(child, 0, 0);

    child->r0 = 0;
    child->pc = (uint32_t)kernel_return_pc;
    child->lr = (uint32_t)kernel_return_pc;
    child->spsr = saved_status;
    arch_task_context_mark_first_run(child);
    arch_task_context_set_returns_to_user(child, false);
}

#endif /* _ASM_TASK_CONTEXT_H */

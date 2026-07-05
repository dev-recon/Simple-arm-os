/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/interrupt/irq_return.c
 * Layer: Kernel / interrupts and scheduler boundary
 *
 * Responsibilities:
 * - Bridge IRQ exit to the normal "return to user" work path.
 * - Deliver pending user signals and consume timer preemption without waiting
 *   for the interrupted task to enter the kernel via a syscall.
 *
 * Notes:
 * - This code must never schedule while still using the banked IRQ stack.
 *   irq_user_work_prepare() only freezes the interrupted user context; the
 *   blocking work happens later in SVC mode on the task kernel stack.
 */

#include <kernel/interrupt.h>
#include <kernel/kernel.h>
#include <kernel/signal.h>
#include <kernel/smp.h>
#include <kernel/task.h>
#include <kernel/timer.h>
#include <asm/arm.h>

static inline void irq_return_enable_interrupts(void)
{
    enable_interrupts();
}

/*
 * IRQ frame layout built by kernel/interrupt/interrupt.S:
 *
 *   word 0      alignment padding
 *   word 1      saved SPSR, i.e. CPSR of the interrupted context
 *   words 2..14 r0-r12 from the interrupted context
 *   word 15     adjusted IRQ LR, i.e. interrupted user PC
 *
 * Keep these constants in lock-step with IRQ_FRAME_* in interrupt.S.
 */
#define IRQ_FRAME_SPSR 1u
#define IRQ_FRAME_R0   2u
#define IRQ_FRAME_PC   15u

static bool task_state_requires_reschedule(task_t* task)
{
    if (!task)
        return false;

    return task->state == TASK_BLOCKED ||
           task->state == TASK_INTERRUPTIBLE ||
           task->state == TASK_UNINTERRUPTIBLE ||
           task->state == TASK_STOPPED ||
           task->state == TASK_ZOMBIE ||
           task->state == TASK_TERMINATED;
}

uint32_t irq_user_work_prepare(uint32_t* irq_frame)
{
    task_t* task = task_current_local();
    uint32_t cpu = smp_processor_id();
    vaddr_t usr_sp;
    vaddr_t usr_lr;

    if (!irq_frame || !task || task->type != TASK_TYPE_PROCESS || !task->process)
        return 0;

    /*
     * Only take this path where the scheduler would be allowed to run. The
     * critical-section flag is per-CPU; seeing it set while returning from user
     * mode means some kernel path left the CPU guarded, so use the fast IRQ
     * return and let the next safe boundary consume the work.
     */
    if (!smp_scheduler_cpu_enabled(cpu) || get_critical_section())
        return 0;

    if (!scheduler_resched_pending_on_cpu(cpu) && !has_pending_signals(task))
        return 0;

    /*
     * Freeze the interrupted user register image in the same canonical context
     * used by syscall.S. From this point the SVC continuation can schedule away
     * and later rebuild the user return exclusively from task->context.usr_*.
     */
    for (uint32_t i = 0; i < 13; i++)
        task->context.usr_r[i] = irq_frame[IRQ_FRAME_R0 + i];
    task->context.usr_pc = irq_frame[IRQ_FRAME_PC];
    task->context.usr_cpsr = irq_frame[IRQ_FRAME_SPSR];

    arm_read_user_sp_lr_from_irq(&usr_sp, &usr_lr);
    task->context.usr_sp = usr_sp;
    task->context.usr_lr = usr_lr;
    task->context.returns_to_user = 1;

    return 1;
}

void irq_user_work_pending(void)
{
    task_t* task = task_current_local();
    signal_check_result_t sig_result = SIGNAL_CHECK_NONE;

    /*
     * We are now in SVC mode on the task kernel stack, so nested IRQs are safe:
     * an IRQ inside this function sees SPSR=SVC and therefore cannot recurse
     * through the return-to-user hook.
     */
    irq_return_enable_interrupts();

    if (task && task->type == TASK_TYPE_PROCESS && task->process) {
        sig_result = check_pending_signals();
        task = task_current_local();
    }

    /*
     * Signal delivery may rewrite ctx->usr_* to enter a user handler. The
     * assembly continuation always returns through ctx->usr_*, so consume the
     * one-shot override exactly like syscall.S does.
     */
    signal_consume_user_return_override();

    task = task_current_local();
    if (!task)
        return;

    if (sig_result == SIGNAL_CHECK_EXITED ||
        sig_result == SIGNAL_CHECK_STOPPED ||
        task_state_requires_reschedule(task)) {
        yield();
        return;
    }

    if (scheduler_take_resched_current_cpu())
        yield();
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/task/context_debug.c
 * Layer: Kernel / ARMv7-A task diagnostics
 *
 * Responsibilities:
 * - Print ARM32 task_context_t register dumps for low-level debugging.
 * - Keep register-layout knowledge out of generic scheduler code.
 *
 * Notes:
 * - This file intentionally knows the concrete ARM32 task_context_t fields.
 *   Portable code should use arch_task_context_* helpers instead.
 */

#include <kernel/task.h>
#include <kernel/process.h>
#include <kernel/kprintf.h>
#include <kernel/uart.h>

void debug_context_registers(task_context_t* ctx, const char* moment)
{
    if (!ctx) {
        KWARN("debug_context_registers: context is NULL\n");
        return;
    }

    KDEBUG("[%s] Context registers:\n", moment);
    KDEBUG("  r0 (arg): 0x%08X (%d)\n", ctx->r0, ctx->r0);
    KDEBUG("  sp:       0x%08X\n", ctx->sp);
    KDEBUG("  lr:       0x%08X\n", ctx->lr);
    KDEBUG("  pc:       0x%08X\n", ctx->pc);
    KDEBUG("  cpsr:     0x%08X\n", ctx->cpsr);
    KDEBUG("  is_first: %u\n", ctx->is_first_run);
}

void debug_print_ctx(task_context_t *context, const char* caller)
{
    if (!context) {
        KWARN("debug_print_ctx: context is NULL\n");
        return;
    }

    kprintf("Current Task (0x%08X) saved Context - Called from %s:\n",
            (uint32_t)context, caller ? caller : "?");
    kprintf("  r0: 0x%08X\n", context->r0);
    kprintf("  r1: 0x%08X\n", context->r1);
    kprintf("  r2: 0x%08X\n", context->r2);
    kprintf("  r3: 0x%08X\n", context->r3);
    kprintf("  r4: 0x%08X\n", context->r4);
    kprintf("  r5: 0x%08X\n", context->r5);
    kprintf("  r6: 0x%08X\n", context->r6);
    kprintf("  r7: 0x%08X\n", context->r7);
    kprintf("  r8: 0x%08X\n", context->r8);
    kprintf("  r9: 0x%08X\n", context->r9);
    kprintf("  r10: 0x%08X\n", context->r10);
    kprintf("  r11: 0x%08X\n", context->r11);
    kprintf("  r12: 0x%08X\n", context->r12);
    kprintf("  SP: 0x%08X\n", context->sp);
    kprintf("  LR: 0x%08X\n", context->lr);
    kprintf("  PC: 0x%08X\n", context->pc);
    kprintf("  CPSR: 0x%02X\n", context->cpsr);
    kprintf("  IS FIRST RUN: 0x%01X\n", context->is_first_run);
    kprintf("  TTBR0: 0x%08X\n", context->ttbr0);
    kprintf("  ASID: 0x%03X\n", context->asid);
    kprintf("  SPSR: 0x%02X\n", context->spsr & 0x1F);
    kprintf("  RETURNS TO USER: 0x%01X\n", context->returns_to_user);

    for (int i = 0; i < 13; i++)
        kprintf("  usr_r[%d]: 0x%08X\n", i, context->usr_r[i]);

    kprintf("  USR SP: 0x%08X\n", context->usr_sp);
    kprintf("  USR LR: 0x%08X\n", context->usr_lr);
    kprintf("  USR PC: 0x%08X\n", context->usr_pc);
    kprintf("  USR CPSR: 0x%02X\n", context->usr_cpsr);

    kprintf("  SVC SP TOP: 0x%08X\n", context->svc_sp_top);
    kprintf("  SVC SP: 0x%08X\n", context->svc_sp);
    kprintf("  SVC LR SAVED : 0x%08X\n", context->svc_lr_saved);
}

__attribute__((noinline))
void debug_return_snapshot(task_context_t *ctx, uint32_t spsr,
                           uint32_t usr_pc, uint32_t tracer)
{
    uart_puts("\n-- Return-to-user snapshot --\n");
    uart_puts("ctx=");
    uart_put_hex((unsigned long)ctx);
    uart_puts(" tracer=");
    uart_put_hex(tracer);
    uart_puts("\n");
    uart_puts("SPSR=");
    uart_put_hex(spsr);
    uart_puts(" (mode=");
    uart_put_hex(spsr & 0x1F);
    uart_puts(" T=");
    uart_put_dec((int)((spsr >> 5) & 1));
    uart_puts(")\n");
    uart_puts("LR_svc(next) = ");
    uart_put_hex(usr_pc);
    uart_puts("\n");
}

void debug_print_task(task_t *task_in)
{
    task_t *task = task_in ? task_in : get_current_task();

    if (!task) {
        KWARN("debug_print_task: task is NULL\n");
        return;
    }

    kprintf("Current Task (%s) saved Context:\n", task->name);
    debug_print_ctx(&task->context, "debug_print_task");
}

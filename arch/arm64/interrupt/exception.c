/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/interrupt/exception.c
 * Layer: ARM64 / exception dispatch
 *
 * Responsibilities:
 * - Dispatch EL1 IRQs and synchronous exceptions from vectors.S.
 * - Implement the bounded bootstrap AArch64 syscall ABI.
 * - Capture the active EL0 register image across syscall entry and return.
 * - Route user yield and exit through the cooperative task dispatcher.
 * - Convert timer IRQ events into deferred preemption at IRQ-return points.
 *
 * Notes:
 * - Console write and controlled exit are bring-up backends, not generic VFS.
 * - Unexpected exceptions print architectural state and halt deterministically.
 */

#include <asm/early_console.h>
#include <asm/exception.h>
#include <asm/exception_frame.h>
#include <asm/irq.h>
#include <kernel/task_runqueue.h>
#include <uapi/armos/syscall.h>

typedef unsigned long long uint64_t;

#define ESR_EC_SHIFT 26u
#define ESR_EC_MASK  0x3fu
#define ESR_EC_SVC64 0x15u
#define ESR_EC_BRK64 0x3cu
#define ARM64_VECTOR_SYNC_CURRENT_SPX 4u
#define ARM64_VECTOR_IRQ_CURRENT_SPX  5u
#define ARM64_VECTOR_SYNC_LOWER_A64   8u
#define ARM64_VECTOR_IRQ_LOWER_A64    9u
#define ARM64_BRK_VECTOR_TEST 0x64u
#define ARM64_SVC_SYSCALL      0u
#define SPSR_EL1H_MASKED       0x3c5u
#define ARM64_BOOTSTRAP_WRITE_MAX 256u

static const arm64_user_vm_t *el0_vm;
static arm64_user_context_t *el0_registers;
static uint64_t el0_exit_address;
static uint64_t el0_exit_status;
static unsigned int el0_syscall_count;
static task_dispatcher_t *active_dispatcher;

void arm64_exception_set_el0_context(const arm64_user_vm_t *vm,
                                     arm64_user_context_t *registers,
                                     arm64_exception_u64 exit_address)
{
    el0_vm = vm;
    el0_registers = registers;
    el0_exit_address = exit_address;
    el0_exit_status = 0;
    el0_syscall_count = 0;
}

void arm64_exception_set_task_dispatcher(task_dispatcher_t *dispatcher)
{
    active_dispatcher = dispatcher;
}

unsigned int arm64_exception_el0_syscall_count(void)
{
    return el0_syscall_count;
}

arm64_exception_u64 arm64_exception_el0_exit_status(void)
{
    return el0_exit_status;
}

static uint64_t syscall_error(unsigned int error)
{
    return 0ULL - (uint64_t)error;
}

static void save_el0_registers(const arm64_user_context_t *registers)
{
    unsigned int index;

    if (!el0_registers)
        return;
    for (index = 0; index < 31; index++)
        el0_registers->x[index] = registers->x[index];
    el0_registers->sp = registers->sp;
    el0_registers->pc = registers->pc;
    el0_registers->pstate = registers->pstate;
}

static void arm64_bootstrap_syscall(arm64_exception_frame_t *frame)
{
    arm64_user_context_t *registers = &frame->user;
    uint64_t number = registers->x[8];

    el0_syscall_count++;
    if (number == ARMOS_NR_SCHED_YIELD) {
        registers->x[0] = 0;
        save_el0_registers(registers);
        if (active_dispatcher &&
            task_dispatcher_yield(active_dispatcher) != 0)
            registers->x[0] = syscall_error(EAGAIN);
        save_el0_registers(registers);
        return;
    }

    if (number == ARMOS_NR_WRITE) {
        uint64_t fd = registers->x[0];
        vaddr_t address = (vaddr_t)registers->x[1];
        size_t length = (size_t)registers->x[2];
        size_t index;

        if (fd != 1 && fd != 2) {
            registers->x[0] = syscall_error(EBADF);
            save_el0_registers(registers);
            return;
        }
        if (registers->x[2] > ARM64_BOOTSTRAP_WRITE_MAX ||
            arm64_user_vm_validate_range(el0_vm, address, length,
                                         ARM64_USER_PAGE_READ) != 0) {
            registers->x[0] = syscall_error(EFAULT);
            save_el0_registers(registers);
            return;
        }
        for (index = 0; index < length; index++)
            arm64_early_putc(*(const char *)(uintptr_t)(address + index));
        registers->x[0] = length;
        save_el0_registers(registers);
        return;
    }

    if (number == ARMOS_NR_EXIT && active_dispatcher != NULL) {
        el0_exit_status = registers->x[0];
        save_el0_registers(registers);
        if (task_dispatcher_block(active_dispatcher) != 0)
            registers->x[0] = syscall_error(EAGAIN);
        save_el0_registers(registers);
        return;
    }

    if (number == ARMOS_NR_EXIT && el0_exit_address != 0) {
        el0_exit_status = registers->x[0];
        save_el0_registers(registers);
        registers->pc = el0_exit_address;
        registers->pstate = SPSR_EL1H_MASKED;
        return;
    }

    registers->x[0] = syscall_error(ENOSYS);
    save_el0_registers(registers);
}

static void arm64_exception_halt(void)
{
    arm64_early_puts("ARM64_EXCEPTION_HALT\n");
    for (;;) {
        __asm__ volatile("wfe");
    }
}

void arm64_exception_dispatch(arm64_exception_frame_t *frame)
{
    uint64_t ec = (frame->esr >> ESR_EC_SHIFT) & ESR_EC_MASK;
    uint64_t iss = frame->esr & 0x01ffffffu;

    if (frame->vector == ARM64_VECTOR_IRQ_CURRENT_SPX ||
        frame->vector == ARM64_VECTOR_IRQ_LOWER_A64) {
        uint32_t events = arm64_irq_dispatch();

        if ((events & ARM64_IRQ_EVENT_TIMER) != 0 &&
            active_dispatcher != NULL) {
            if (task_dispatcher_request_preempt(active_dispatcher) != 0 ||
                task_dispatcher_service_preempt_at_safe_point(
                    active_dispatcher) != 0)
                arm64_exception_halt();
        }
        return;
    }

    if (frame->vector == ARM64_VECTOR_SYNC_LOWER_A64 &&
        ec == ESR_EC_SVC64 && (frame->user.pstate & 0xfu) == 0) {
        uint64_t immediate = iss & 0xffffu;

        if (immediate == ARM64_SVC_SYSCALL && el0_vm != NULL) {
            arm64_bootstrap_syscall(frame);
            return;
        }
    }

    arm64_early_puts("Exception vector: ");
    arm64_early_puthex64(frame->vector);
    arm64_early_puts("\nESR_EL1: ");
    arm64_early_puthex64(frame->esr);
    arm64_early_puts(" EC: ");
    arm64_early_puthex64(ec);
    arm64_early_puts("\nELR_EL1: ");
    arm64_early_puthex64(frame->user.pc);
    arm64_early_puts(" FAR_EL1: ");
    arm64_early_puthex64(frame->far);
    arm64_early_puts("\nSPSR_EL1: ");
    arm64_early_puthex64(frame->user.pstate);
    arm64_early_puts("\n");

    if (frame->vector == ARM64_VECTOR_SYNC_CURRENT_SPX &&
        ec == ESR_EC_BRK64 &&
        (iss & 0xffffu) == ARM64_BRK_VECTOR_TEST) {
        frame->user.pc += 4;
        arm64_early_puts("ARM64_VECTOR_OK\n");
        return;
    }

    arm64_exception_halt();
}

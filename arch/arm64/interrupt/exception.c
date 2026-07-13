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
 * - Decode the AArch64 syscall ABI and invoke the generic syscall dispatcher.
 * - Capture the active EL0 register image across syscall entry and return.
 * - Validate user buffers through the active generic vm_space_t identity.
 * - Route lower-EL translation faults to the active VM page-fault backend.
 * - Route user yield and exit through the cooperative task dispatcher.
 * - Invoke scheduler wakeup policy on physical-timer ticks.
 * - Convert timer IRQ events into deferred preemption at IRQ-return points.
 *
 * Notes:
 * - A bounded fallback remains available before the generic table is enabled.
 * - Console write and controlled exit are bring-up backends, not generic VFS.
 * - Unexpected exceptions print architectural state and halt deterministically.
 */

#include <asm/early_console.h>
#include <asm/exception.h>
#include <asm/exception_frame.h>
#include <asm/irq.h>
#include <asm/user_vm.h>
#include <kernel/task_runqueue.h>
#include <uapi/armos/syscall.h>

typedef unsigned long long uint64_t;

#define ESR_EC_SHIFT 26u
#define ESR_EC_MASK  0x3fu
#define ESR_EC_SVC64 0x15u
#define ESR_EC_INSN_ABORT_LOWER 0x20u
#define ESR_EC_DATA_ABORT_LOWER 0x24u
#define ESR_EC_BRK64 0x3cu
#define ARM64_VECTOR_SYNC_CURRENT_SPX 4u
#define ARM64_VECTOR_IRQ_CURRENT_SPX  5u
#define ARM64_VECTOR_SYNC_LOWER_A64   8u
#define ARM64_VECTOR_IRQ_LOWER_A64    9u
#define ARM64_BRK_VECTOR_TEST 0x64u
#define ARM64_SVC_SYSCALL      0u
#define SPSR_EL1H_MASKED       0x3c5u
#define ARM64_BOOTSTRAP_WRITE_MAX 256u

static const vm_space_t *el0_vm_space;
static arm64_user_context_t *el0_registers;
static const vm_space_t *pending_exec_vm_space;
static arm64_user_context_t *pending_exec_registers;
static arm64_exec_commit_hook_t pending_exec_commit_hook;
static void *pending_exec_commit_owner;
static uint64_t el0_exit_address;
static uint64_t el0_exit_status;
static unsigned int el0_syscall_count;
static task_dispatcher_t *active_dispatcher;
static syscall_dispatcher_t *active_syscall_dispatcher;
static arm64_timer_tick_hook_t active_timer_tick_hook;
static arm64_page_fault_hook_t active_page_fault_hook;

void arm64_exception_set_el0_context(const vm_space_t *vm_space,
                                     arm64_user_context_t *registers,
                                     arm64_exception_u64 exit_address)
{
    el0_vm_space = vm_space;
    el0_registers = registers;
    el0_exit_address = exit_address;
    el0_exit_status = 0;
    el0_syscall_count = 0;
    pending_exec_vm_space = NULL;
    pending_exec_registers = NULL;
    pending_exec_commit_hook = NULL;
    pending_exec_commit_owner = NULL;
}

int arm64_exception_request_exec(const vm_space_t *vm_space,
                                 arm64_user_context_t *registers,
                                 arm64_exec_commit_hook_t commit_hook,
                                 void *commit_owner)
{
    if (!vm_space || !registers || pending_exec_vm_space ||
        pending_exec_registers)
        return -1;
    pending_exec_vm_space = vm_space;
    pending_exec_registers = registers;
    pending_exec_commit_hook = commit_hook;
    pending_exec_commit_owner = commit_owner;
    return 0;
}

void arm64_exception_set_task_dispatcher(task_dispatcher_t *dispatcher)
{
    active_dispatcher = dispatcher;
}

void arm64_exception_set_syscall_dispatcher(
    syscall_dispatcher_t *dispatcher)
{
    active_syscall_dispatcher = dispatcher;
}

void arm64_exception_set_timer_tick_hook(arm64_timer_tick_hook_t hook)
{
    active_timer_tick_hook = hook;
}

void arm64_exception_set_page_fault_hook(arm64_page_fault_hook_t hook)
{
    active_page_fault_hook = hook;
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

static void restore_el0_registers(arm64_user_context_t *destination,
                                  const arm64_user_context_t *source)
{
    unsigned int index;

    for (index = 0; index < 31; index++)
        destination->x[index] = source->x[index];
    destination->sp = source->sp;
    destination->pc = source->pc;
    destination->pstate = source->pstate;
}

static void arm64_bootstrap_syscall(arm64_exception_frame_t *frame)
{
    arm64_user_context_t *registers = &frame->user;
    uint64_t number = registers->x[8];

    if (active_syscall_dispatcher != NULL) {
        syscall_request_t request;
        syscall_result_t result;
        uint64_t exit_argument = registers->x[0];
        unsigned int index;

        request.number = (uint32_t)number;
        for (index = 0; index < ARMOS_SYSCALL_ARGUMENT_COUNT; index++)
            request.arguments[index] = registers->x[index];
        el0_syscall_count++;
        result = syscall_dispatcher_dispatch(active_syscall_dispatcher,
                                             &request);
        registers->x[0] = (uint64_t)result;
        if (number == ARMOS_NR_EXECVE && result == 0 &&
            pending_exec_vm_space && pending_exec_registers) {
            const vm_space_t *new_vm = pending_exec_vm_space;
            const vm_space_t *previous_vm = el0_vm_space;
            arm64_user_context_t *new_registers = pending_exec_registers;
            arm64_exec_commit_hook_t commit_hook =
                pending_exec_commit_hook;
            void *commit_owner = pending_exec_commit_owner;

            pending_exec_vm_space = NULL;
            pending_exec_registers = NULL;
            pending_exec_commit_hook = NULL;
            pending_exec_commit_owner = NULL;
            if (arm64_user_vm_activate_space(new_vm) != 0) {
                registers->x[0] = syscall_error(EFAULT);
                save_el0_registers(registers);
                return;
            }
            el0_vm_space = new_vm;
            el0_registers = new_registers;
            restore_el0_registers(registers, new_registers);
            if (commit_hook)
                commit_hook(previous_vm, commit_owner);
            return;
        }
        save_el0_registers(registers);

        if (number == ARMOS_NR_SCHED_YIELD && result == 0 &&
            active_dispatcher != NULL &&
            task_dispatcher_yield(active_dispatcher) != 0)
            registers->x[0] = syscall_error(EAGAIN);
        if (number == ARMOS_NR_EXIT && result == 0) {
            el0_exit_status = exit_argument;
            registers->x[0] = exit_argument;
            save_el0_registers(registers);
            if (active_dispatcher != NULL) {
                if (task_dispatcher_block(active_dispatcher) != 0) {
                    registers->x[0] = syscall_error(EAGAIN);
                    save_el0_registers(registers);
                }
            } else if (el0_exit_address != 0) {
                registers->pc = el0_exit_address;
                registers->pstate = SPSR_EL1H_MASKED;
                return;
            }
        }
        save_el0_registers(registers);
        return;
    }

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
            arm64_user_vm_validate_space_range(
                el0_vm_space, address, length,
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

        if ((events & ARM64_IRQ_EVENT_TIMER) != 0) {
            if ((active_timer_tick_hook != NULL &&
                 active_timer_tick_hook(arm64_timer_irq_ticks()) != 0) ||
                (active_dispatcher != NULL &&
                 (task_dispatcher_timer_tick(active_dispatcher) != 0 ||
                  task_dispatcher_service_preempt_at_safe_point(
                      active_dispatcher) != 0)))
                arm64_exception_halt();
        }
        return;
    }

    if (frame->vector == ARM64_VECTOR_SYNC_LOWER_A64 &&
        ec == ESR_EC_SVC64 && (frame->user.pstate & 0xfu) == 0) {
        uint64_t immediate = iss & 0xffffu;

        if (immediate == ARM64_SVC_SYSCALL && el0_vm_space != NULL) {
            arm64_bootstrap_syscall(frame);
            return;
        }
    }

    if (frame->vector == ARM64_VECTOR_SYNC_LOWER_A64 &&
        active_page_fault_hook != NULL &&
        (ec == ESR_EC_DATA_ABORT_LOWER ||
         ec == ESR_EC_INSN_ABORT_LOWER)) {
        unsigned int fault_status = (unsigned int)(iss & 0x3fu);
        int is_translation_fault = fault_status >= 4u && fault_status <= 7u;
        int is_write = ec == ESR_EC_DATA_ABORT_LOWER &&
                       (iss & (1u << 6)) != 0;

        if (is_translation_fault &&
            active_page_fault_hook((vaddr_t)frame->far, is_write,
                                   ec == ESR_EC_INSN_ABORT_LOWER) == 0)
            return;
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

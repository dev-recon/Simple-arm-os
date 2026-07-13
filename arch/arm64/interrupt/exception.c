/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Early AArch64 synchronous exception diagnostics.
 */

#include <asm/early_console.h>
#include <asm/exception.h>
#include <asm/irq.h>
#include <uapi/armos/syscall.h>

typedef unsigned long long uint64_t;

typedef struct {
    uint64_t x[31];
    uint64_t elr;
    uint64_t spsr;
    uint64_t esr;
    uint64_t far;
    uint64_t vector;
} arm64_exception_frame_t;

_Static_assert(sizeof(arm64_exception_frame_t) == 288,
               "AArch64 exception frame must match vectors.S");

#define ESR_EC_SHIFT 26u
#define ESR_EC_MASK  0x3fu
#define ESR_EC_SVC64 0x15u
#define ESR_EC_BRK64 0x3cu
#define ARM64_VECTOR_SYNC_CURRENT_SPX 4u
#define ARM64_VECTOR_IRQ_CURRENT_SPX  5u
#define ARM64_VECTOR_SYNC_LOWER_A64   8u
#define ARM64_BRK_VECTOR_TEST 0x64u
#define ARM64_SVC_SYSCALL      0u
#define SPSR_EL1H_MASKED       0x3c5u
#define ARM64_BOOTSTRAP_WRITE_MAX 256u

static const arm64_user_vm_t *el0_vm;
static uint64_t el0_exit_address;
static uint64_t el0_exit_status;
static unsigned int el0_syscall_count;

void arm64_exception_set_el0_context(const arm64_user_vm_t *vm,
                                     arm64_exception_u64 exit_address)
{
    el0_vm = vm;
    el0_exit_address = exit_address;
    el0_exit_status = 0;
    el0_syscall_count = 0;
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

static void arm64_bootstrap_syscall(arm64_exception_frame_t *frame)
{
    uint64_t number = frame->x[8];

    el0_syscall_count++;
    if (number == ARMOS_NR_WRITE) {
        uint64_t fd = frame->x[0];
        vaddr_t address = (vaddr_t)frame->x[1];
        size_t length = (size_t)frame->x[2];
        size_t index;

        if (fd != 1 && fd != 2) {
            frame->x[0] = syscall_error(EBADF);
            return;
        }
        if (frame->x[2] > ARM64_BOOTSTRAP_WRITE_MAX ||
            arm64_user_vm_validate_range(el0_vm, address, length,
                                         ARM64_USER_PAGE_READ) != 0) {
            frame->x[0] = syscall_error(EFAULT);
            return;
        }
        for (index = 0; index < length; index++)
            arm64_early_putc(*(const char *)(uintptr_t)(address + index));
        frame->x[0] = length;
        return;
    }

    if (number == ARMOS_NR_EXIT && el0_exit_address != 0) {
        el0_exit_status = frame->x[0];
        frame->elr = el0_exit_address;
        frame->spsr = SPSR_EL1H_MASKED;
        return;
    }

    frame->x[0] = syscall_error(ENOSYS);
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

    if (frame->vector == ARM64_VECTOR_IRQ_CURRENT_SPX) {
        arm64_irq_dispatch();
        return;
    }

    if (frame->vector == ARM64_VECTOR_SYNC_LOWER_A64 &&
        ec == ESR_EC_SVC64 && (frame->spsr & 0xfu) == 0) {
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
    arm64_early_puthex64(frame->elr);
    arm64_early_puts(" FAR_EL1: ");
    arm64_early_puthex64(frame->far);
    arm64_early_puts("\nSPSR_EL1: ");
    arm64_early_puthex64(frame->spsr);
    arm64_early_puts("\n");

    if (frame->vector == ARM64_VECTOR_SYNC_CURRENT_SPX &&
        ec == ESR_EC_BRK64 &&
        (iss & 0xffffu) == ARM64_BRK_VECTOR_TEST) {
        frame->elr += 4;
        arm64_early_puts("ARM64_VECTOR_OK\n");
        return;
    }

    arm64_exception_halt();
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Early AArch64 synchronous exception diagnostics.
 */

#include <asm/early_console.h>
#include <asm/irq.h>

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
#define ESR_EC_BRK64 0x3cu
#define ARM64_VECTOR_SYNC_CURRENT_SPX 4u
#define ARM64_VECTOR_IRQ_CURRENT_SPX  5u
#define ARM64_BRK_VECTOR_TEST 0x64u

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

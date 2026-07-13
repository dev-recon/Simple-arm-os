/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/irq.h
 * Layer: ARM64 / interrupt state
 *
 * Responsibilities:
 * - Save and mask the local EL1 IRQ/FIQ state through DAIF.
 * - Restore a previously saved local interrupt-mask state.
 * - Declare the bootstrap IRQ dispatcher and timer probe.
 *
 * Notes:
 * - Generic code treats the saved state as opaque; only DAIF I/F bits are
 *   changed by the save operation.
 */

#ifndef ARMOS_ARM64_IRQ_H
#define ARMOS_ARM64_IRQ_H

#include <kernel/types.h>

static inline uint32_t asm_irq_fiq_save(void)
{
    uint64_t saved_state;

    __asm__ volatile(
        "mrs %0, daif\n"
        "msr daifset, #3"
        : "=r"(saved_state)
        :
        : "memory");
    return (uint32_t)saved_state;
}

static inline void asm_irq_fiq_restore(uint32_t saved_state)
{
    uint64_t state = saved_state;

    __asm__ volatile("msr daif, %0" :: "r"(state) : "memory");
}

void arm64_irq_dispatch(void);
int arm64_timer_irq_smoke_test(void);

#endif /* ARMOS_ARM64_IRQ_H */

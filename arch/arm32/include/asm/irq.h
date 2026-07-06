/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/irq.h
 * Layer: ARM32 / IRQ local state helpers
 *
 * Responsibilities:
 * - Provide ARM32 local IRQ/FIQ mask save/restore primitives to the generic
 *   arch IRQ boundary.
 * - Keep ARM-specific CPSR helper names out of include/kernel/arch_irq.h.
 */

#ifndef _ASM_ARM32_IRQ_H
#define _ASM_ARM32_IRQ_H

#include <kernel/types.h>
#include <asm/arm.h>

static inline uint32_t asm_irq_fiq_save(void)
{
    return arm_disable_irq_fiq_save();
}

static inline void asm_irq_fiq_restore(uint32_t saved_state)
{
    arm_restore_cpsr_control(saved_state);
}

#endif /* _ASM_ARM32_IRQ_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_irq.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose local interrupt mask save/restore primitives with generic names.
 * - Keep scheduler and process code from including ARM helper headers only to
 *   enter or leave small critical sections.
 *
 * Notes:
 * - The saved value is architecture-defined. Callers must treat it as an
 *   opaque token and restore it with the matching function.
 */

#ifndef _KERNEL_ARCH_IRQ_H
#define _KERNEL_ARCH_IRQ_H

#include <kernel/types.h>
#include <asm/arm.h>

static inline uint32_t arch_irq_fiq_save(void)
{
    return arm_disable_irq_fiq_save();
}

static inline void arch_irq_fiq_restore(uint32_t saved_state)
{
    arm_restore_cpsr_control(saved_state);
}

#endif /* _KERNEL_ARCH_IRQ_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/spinlock.h
 * Layer: ARM32 / spinlock primitives
 *
 * Responsibilities:
 * - Provide atomic acquire/release helpers for generic spinlock code.
 * - Hide ARM LDREX/STREX, WFE/SEV, and interrupt-mask details.
 *
 * Notes:
 * - The generic spinlock keeps ownership/debug policy; this header only
 *   supplies CPU instructions and ordering.
 */

#ifndef _ASM_ARM32_SPINLOCK_H
#define _ASM_ARM32_SPINLOCK_H

#include <asm/arm.h>

#define ARCH_SPIN_IRQ_MASK 0xC0UL /* CPSR I/F bits */

static inline int arch_spin_try_acquire(volatile uint32_t* locked)
{
    return arm_spin_try_acquire(locked);
}

static inline void arch_spin_wait(void)
{
    wait_for_event();
}

static inline void arch_spin_wake(void)
{
    send_event();
}

static inline void arch_spin_memory_barrier(void)
{
    data_memory_barrier();
}

static inline void arch_spin_post_unlock_barrier(void)
{
    data_sync_barrier();
}

static inline unsigned long arch_spin_irq_save(void)
{
    return arm_disable_irq_save() & ARCH_SPIN_IRQ_MASK;
}

static inline void arch_spin_irq_restore(unsigned long flags)
{
    arm_restore_irq_mask((uint32_t)flags, ARCH_SPIN_IRQ_MASK);
}

#endif /* _ASM_ARM32_SPINLOCK_H */

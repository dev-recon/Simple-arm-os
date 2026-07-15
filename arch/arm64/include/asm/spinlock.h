/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/spinlock.h
 * Layer: ARM64 / CPU atomic primitives
 *
 * Responsibilities:
 * - Supply exclusive acquire/release primitives to common spinlock policy.
 * - Save and restore the local DAIF interrupt mask around IRQ-safe locks.
 *
 * Notes:
 * - Lock ownership, diagnostics and recursion policy remain in kernel/sync.
 */

#ifndef ASM_ARM64_SPINLOCK_H
#define ASM_ARM64_SPINLOCK_H

#include <kernel/types.h>

static inline int arch_spin_try_acquire(volatile uint32_t *locked)
{
    uint32_t value;
    uint32_t failed;

    __asm__ volatile(
        "ldaxr %w0, [%2]\n"
        "cbnz %w0, 1f\n"
        "mov %w0, #1\n"
        "stxr %w1, %w0, [%2]\n"
        "b 2f\n"
        "1: mov %w1, #1\n"
        "2:"
        : "=&r"(value), "=&r"(failed)
        : "r"(locked)
        : "memory");
    return failed == 0;
}

static inline void arch_spin_wait(void)
{
    __asm__ volatile("wfe" ::: "memory");
}

static inline void arch_spin_wake(void)
{
    __asm__ volatile("sev" ::: "memory");
}

static inline void arch_spin_memory_barrier(void)
{
    __asm__ volatile("dmb ish" ::: "memory");
}

static inline void arch_spin_post_unlock_barrier(void)
{
    __asm__ volatile("dsb ish" ::: "memory");
}

static inline unsigned long arch_spin_irq_save(void)
{
    uint64_t saved;

    __asm__ volatile(
        "mrs %0, daif\n"
        "msr daifset, #3"
        : "=r"(saved)
        :
        : "memory");
    return (unsigned long)saved;
}

static inline void arch_spin_irq_restore(unsigned long flags)
{
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
}

#endif /* ASM_ARM64_SPINLOCK_H */

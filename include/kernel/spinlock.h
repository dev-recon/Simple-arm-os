/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/spinlock.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H

#include <kernel/types.h>

/*
 * SMP spinlock.
 *
 * The lock word is acquired with architecture-provided atomic primitives.
 * owner stores the CPU id that owns the lock, or SPINLOCK_NO_OWNER when the
 * lock is free.  This stays useful even before secondary CPUs are enabled:
 * it makes accidental recursive locking and future SMP bugs visible.
 */
#define SPINLOCK_NO_OWNER 0xFFFFFFFFU

typedef struct spinlock {
    volatile uint32_t locked;    /* 0 = free, 1 = held */
    uint32_t owner;              /* owning CPU id, or SPINLOCK_NO_OWNER */
    uint32_t count;              /* total successful acquisitions, debug only */
    const char* name;            /* debug name */
} __attribute__((aligned(4))) spinlock_t;

#define SPINLOCK_INIT(lock_name) { \
    .locked = 0, \
    .owner = SPINLOCK_NO_OWNER, \
    .count = 0, \
    .name = lock_name \
}

#define DEFINE_SPINLOCK(name) \
    spinlock_t name = SPINLOCK_INIT(#name)

void init_spinlock(spinlock_t* lock);
void init_spinlock_named(spinlock_t* lock, const char* name);

void spin_lock(spinlock_t* lock);
void spin_unlock(spinlock_t* lock);
int spin_trylock(spinlock_t* lock);

void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags);
void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags);

int spin_is_locked(spinlock_t* lock);
void spin_dump_info(spinlock_t* lock);
const char* spin_get_name(spinlock_t* lock);

#ifdef DEBUG_SPINLOCKS
#define spin_lock(lock) do { \
    spin_debug_check_recursive(lock); \
    spin_lock(lock); \
} while(0)
void spin_debug_check_recursive(spinlock_t* lock);
#endif

#endif /* _KERNEL_SPINLOCK_H */

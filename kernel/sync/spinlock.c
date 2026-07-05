/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/sync/spinlock.c
 * Layer: Kernel / synchronization
 *
 * Responsibilities:
 * - Provide low-level locking primitives.
 * - Protect shared kernel state across preemption and interrupts.
 *
 * Notes:
 * - Locking changes can expose scheduler and interrupt races.
 */

#include <kernel/spinlock.h>
#include <kernel/smp.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <asm/arm.h>

static inline int spin_atomic_try_acquire(volatile uint32_t* locked)
{
    return arm_spin_try_acquire(locked);
}

void init_spinlock(spinlock_t* lock)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = SPINLOCK_NO_OWNER;
    lock->count = 0;
    lock->name = "unnamed";
}

void init_spinlock_named(spinlock_t* lock, const char* name)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = SPINLOCK_NO_OWNER;
    lock->count = 0;
    lock->name = name ? name : "unnamed";
}

void spin_lock(spinlock_t* lock)
{
    if (!lock) return;

    for (;;) {
        if (spin_atomic_try_acquire(&lock->locked))
            break;

        /*
         * Do not burn the interconnect while another CPU owns the lock.
         * spin_unlock() emits SEV after releasing the word.
         */
        wait_for_event();
    }

    data_memory_barrier();
    lock->owner = smp_processor_id();
    lock->count++;
}

void spin_unlock(spinlock_t* lock)
{
    if (!lock) return;
    
    if (!lock->locked) {
        KERROR("spin_unlock: Lock '%s' not held!\n", lock->name);
        return;
    }

    if (lock->owner != smp_processor_id()) {
        KERROR("spin_unlock: CPU%u releasing lock '%s' owned by CPU%u\n",
               smp_processor_id(), lock->name, lock->owner);
    }

    lock->owner = SPINLOCK_NO_OWNER;
    data_memory_barrier();
    lock->locked = 0;
    data_sync_barrier();
    send_event();
}

int spin_trylock(spinlock_t* lock)
{
    if (!lock) return 0;
    
    if (spin_atomic_try_acquire(&lock->locked)) {
        data_memory_barrier();
        lock->owner = smp_processor_id();
        lock->count++;
        return 1;
    }

    return 0;
}

void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags)
{
    if (!lock || !flags) return;

    const unsigned long IF_MASK = 0xC0UL; /* bits 7 (I) et 6 (F) */
    unsigned long cpsr = arm_disable_irq_save();

    *flags = cpsr & IF_MASK;
    spin_lock(lock);
}

void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags)
{
    if (!lock) return;
    
    spin_unlock(lock);

    const unsigned long IF_MASK = 0xC0UL; /* bits 7 (I) et 6 (F) */
    arm_restore_irq_mask(flags, IF_MASK);
}

int spin_is_locked(spinlock_t* lock)
{
    if (!lock) return 0;
    
    return lock->locked != 0;
}

void spin_dump_info(spinlock_t* lock)
{
    if (!lock) {
        KINFO("spin_dump_info: NULL lock\n");
        return;
    }
    
    KINFO("=== Spinlock Info ===\n");
    KINFO("  Name:     %s\n", lock->name);
    KINFO("  Locked:   %s\n", lock->locked ? "YES" : "NO");
    if (lock->owner == SPINLOCK_NO_OWNER)
        KINFO("  Owner:    none\n");
    else
        KINFO("  Owner:    CPU%u\n", lock->owner);
    KINFO("  Count:    %u\n", lock->count);
    KINFO("  Address:  %p\n", lock);
    KINFO("====================\n");
}

const char* spin_get_name(spinlock_t* lock)
{
    return lock ? lock->name : "NULL";
}

#ifdef DEBUG_SPINLOCKS
void spin_debug_check_recursive(spinlock_t* lock)
{
    if (!lock) return;
    
    if (lock->locked && lock->owner == smp_processor_id()) {
        KERROR("DEADLOCK: Recursive lock attempt on '%s'!\n", lock->name);
        spin_dump_info(lock);
        while (1) wait_for_event();
    }
}
#endif

/**
 * Test des spinlocks
 */
void test_spinlocks(void)
{
    DEFINE_SPINLOCK(test_lock);
    unsigned long flags;
    
    KINFO("=== Test des Spinlocks ===\n");
    
    /* Test basic */
    KINFO("Test 1: Acquisition/liberation basique\n");
    spin_dump_info(&test_lock);
    
    spin_lock(&test_lock);
    KINFO("Lock acquis\n");
    spin_dump_info(&test_lock);
    
    spin_unlock(&test_lock);
    KINFO("Lock libere\n");
    spin_dump_info(&test_lock);
    
    /* Test trylock */
    KINFO("Test 2: Try lock\n");
    if (spin_trylock(&test_lock)) {
        KINFO("Trylock reussi\n");
        spin_unlock(&test_lock);
    } else {
        KINFO("Trylock echoue\n");
    }
    
    /* Test avec interruptions */
    KINFO("Test 3: Lock avec interruptions\n");
    spin_lock_irqsave(&test_lock, &flags);
    KINFO("Lock avec IRQ save acquis\n");
    spin_unlock_irqrestore(&test_lock, flags);
    KINFO("Lock avec IRQ restore libere\n");
    
    KINFO("=== Tests termines ===\n");
}

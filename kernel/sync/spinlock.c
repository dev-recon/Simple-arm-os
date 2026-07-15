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
#include <kernel/arch_spinlock.h>
#include <kernel/smp.h>
#include <kernel/kprintf.h>

static inline int spin_atomic_try_acquire(volatile uint32_t* locked)
{
    return arch_spin_try_acquire(locked);
}

static void spin_lock_record(spinlock_t* lock, const void* caller)
{
    arch_spin_memory_barrier();
    lock->owner = smp_processor_id();
    lock->owner_pc = caller;
    lock->count++;
}

static void spin_unlock_record(spinlock_t* lock, const void* caller)
{
    uint32_t cpu;
    uint32_t owner;
    uint32_t locked;
    const void* owner_pc;

    if (!lock) return;

    cpu = smp_processor_id();
    owner = lock->owner;
    owner_pc = lock->owner_pc;
    locked = lock->locked;

    if (!locked) {
        KERROR("spin_unlock: Lock '%s' not held! cpu=%u owner=%u caller=%p owner_pc=%p lock=%p\n",
               lock->name, cpu, owner, caller, owner_pc, lock);
        return;
    }

    if (owner != cpu) {
        KERROR("spin_unlock: CPU%u releasing lock '%s' owned by CPU%u caller=%p owner_pc=%p lock=%p\n",
               cpu, lock->name, owner, caller, owner_pc, lock);
        /*
         * Releasing here corrupts the lock for the real owner and turns one
         * mismatch into allocator/TLB/task-list damage across all CPUs.
         */
        return;
    }

    lock->owner_pc = 0;
    lock->owner = SPINLOCK_NO_OWNER;
    arch_spin_memory_barrier();
    lock->locked = 0;
    arch_spin_post_unlock_barrier();
    arch_spin_wake();
}

void init_spinlock(spinlock_t* lock)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = SPINLOCK_NO_OWNER;
    lock->count = 0;
    lock->name = "unnamed";
    lock->owner_pc = 0;
}

void init_spinlock_named(spinlock_t* lock, const char* name)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = SPINLOCK_NO_OWNER;
    lock->count = 0;
    lock->name = name ? name : "unnamed";
    lock->owner_pc = 0;
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
        arch_spin_wait();
    }

    spin_lock_record(lock, __builtin_return_address(0));
}

void spin_unlock(spinlock_t* lock)
{
    spin_unlock_record(lock, __builtin_return_address(0));
}

int spin_trylock(spinlock_t* lock)
{
    if (!lock) return 0;
    
    if (spin_atomic_try_acquire(&lock->locked)) {
        spin_lock_record(lock, __builtin_return_address(0));
        return 1;
    }

    return 0;
}

void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags)
{
    if (!lock || !flags) return;

    *flags = arch_spin_irq_save();
    for (;;) {
        if (spin_atomic_try_acquire(&lock->locked))
            break;
        arch_spin_wait();
    }
    spin_lock_record(lock, __builtin_return_address(0));
}

void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags)
{
    if (!lock) return;
    
    spin_unlock_record(lock, __builtin_return_address(0));

    arch_spin_irq_restore(flags);
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
    KINFO("  Owner PC: %p\n", lock->owner_pc);
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

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/mmu/tlb.c
 * Layer: ARM64 / TLB maintenance
 *
 * Responsibilities:
 * - Implement global, VA and ASID invalidation with inner-shareable TLBI.
 * - Publish completed broadcast generations to common SMP diagnostics.
 *
 * Notes:
 * - AArch64 TLBI *IS operations are hardware broadcast rendezvous; no software
 *   IPI acknowledgement protocol is required for these invalidations.
 */

#include <kernel/smp.h>
#include <kernel/spinlock.h>
#include <kernel/tlb.h>

#define TTBR_ASID_SHIFT 48u

static volatile uint32_t total_count;
static volatile uint32_t remote_count;
static volatile uint32_t generation;
static volatile uint32_t cpu_ack[ARMOS_MAX_CPUS];
static spinlock_t counter_lock = SPINLOCK_INIT("arm64_tlb");

static void complete_broadcast(void)
{
    unsigned long flags;
    uint32_t next;
    uint32_t cpu;
    uint32_t participants = 0;

    spin_lock_irqsave(&counter_lock, &flags);
    next = ++generation;
    total_count++;
    for (cpu = 0; cpu < smp_possible_cpu_count() && cpu < ARMOS_MAX_CPUS;
         cpu++) {
        if (!smp_cpu_seen(cpu))
            continue;
        cpu_ack[cpu] = next;
        participants++;
    }
    if (participants > 1)
        remote_count += participants - 1u;
    spin_unlock_irqrestore(&counter_lock, flags);
}

static void finish_tlbi(void)
{
    __asm__ volatile("dsb ish\n\tisb" ::: "memory");
    complete_broadcast();
}

void tlb_shootdown_all(void)
{
    __asm__ volatile("dsb ishst\n\ttlbi vmalle1is" ::: "memory");
    finish_tlbi();
}

void tlb_shootdown_page(vaddr_t vaddr)
{
    uint64_t operand = (uint64_t)vaddr >> 12;

    __asm__ volatile("dsb ishst\n\ttlbi vaae1is, %0" :: "r"(operand) :
                     "memory");
    finish_tlbi();
}

void tlb_shootdown_page_asid(vaddr_t vaddr, uint32_t asid)
{
    uint64_t operand = ((uint64_t)asid << TTBR_ASID_SHIFT) |
                       ((uint64_t)vaddr >> 12);

    __asm__ volatile("dsb ishst\n\ttlbi vae1is, %0" :: "r"(operand) :
                     "memory");
    finish_tlbi();
}

void tlb_shootdown_asid(uint32_t asid)
{
    uint64_t operand = (uint64_t)asid << TTBR_ASID_SHIFT;

    __asm__ volatile("dsb ishst\n\ttlbi aside1is, %0" :: "r"(operand) :
                     "memory");
    finish_tlbi();
}

void tlb_handle_remote_ipi(uint32_t cpu_id)
{
    (void)cpu_id;
}

uint32_t tlb_shootdown_total_count(void) { return total_count; }
uint32_t tlb_shootdown_remote_count(void) { return remote_count; }
uint32_t tlb_shootdown_deferred_count(void) { return 0; }
uint32_t tlb_shootdown_generation(void) { return generation; }

uint32_t tlb_shootdown_cpu_ack(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS ? cpu_ack[cpu_id] : 0;
}

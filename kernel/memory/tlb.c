/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/memory/tlb.c
 * Layer: Kernel / MMU and SMP coordination
 *
 * Responsibilities:
 * - Centralize TLB invalidation requests.
 * - Preserve today's single-online-CPU behavior.
 * - Provide a narrow future hook for SMP remote shootdown.
 *
 * Notes:
 * - CPU1 can be started into the holding pen, but only CPU0 is online. That
 *   means local invalidation is still architecturally sufficient today.
 */

#include <kernel/tlb.h>
#include <kernel/smp.h>
#include <kernel/kprintf.h>
#include <asm/mmu.h>

static volatile uint32_t shootdown_total_count;
static volatile uint32_t shootdown_remote_count;
static volatile uint32_t shootdown_deferred_count;

static bool tlb_remote_required(void)
{
    return smp_online_cpu_count() > 1;
}

static void tlb_note_request(void)
{
    shootdown_total_count++;

    if (tlb_remote_required()) {
        /*
         * This path is intentionally loud. Running user address spaces on more
         * than one CPU without remote TLB shootdown is unsafe: stale entries can
         * survive page-table changes on another core.
         */
        shootdown_deferred_count++;
        KWARN("TLB: remote shootdown not implemented for %u online CPUs\n",
              smp_online_cpu_count());
    }
}

void tlb_shootdown_all(void)
{
    tlb_note_request();
    tlb_flush_all();
}

void tlb_shootdown_page(uint32_t vaddr)
{
    tlb_note_request();
    tlb_flush_by_va_asid(vaddr, 0);
}

void tlb_shootdown_page_asid(uint32_t vaddr, uint32_t asid)
{
    tlb_note_request();
    tlb_flush_by_va_asid(vaddr, asid);
}

void tlb_shootdown_asid(uint32_t asid)
{
    tlb_note_request();
    tlb_flush_by_asid(asid);
}

uint32_t tlb_shootdown_total_count(void)
{
    return shootdown_total_count;
}

uint32_t tlb_shootdown_remote_count(void)
{
    return shootdown_remote_count;
}

uint32_t tlb_shootdown_deferred_count(void)
{
    return shootdown_deferred_count;
}

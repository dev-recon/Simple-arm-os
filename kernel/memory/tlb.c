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
 * - Flush locally on the requesting CPU.
 * - Send bounded SGI rendezvous requests to CPUs that may need the flush.
 *
 * Notes:
 * - CPU1 can be started into the holding pen, but only CPU0 runs the scheduler.
 *   Remote shootdown exists now so the MMU path is ready before user tasks can
 *   ever migrate to another CPU.
 */

#include <kernel/tlb.h>
#include <kernel/smp.h>
#include <kernel/kprintf.h>
#include <kernel/interrupt.h>
#include <kernel/memory.h>
#include <asm/mmu.h>
#include <asm/arm.h>

static volatile uint32_t shootdown_total_count;
static volatile uint32_t shootdown_remote_count;
static volatile uint32_t shootdown_deferred_count;

typedef enum {
    TLB_REQ_NONE = 0,
    TLB_REQ_ALL,
    TLB_REQ_PAGE,
    TLB_REQ_PAGE_ASID,
    TLB_REQ_ASID,
} tlb_request_kind_t;

static volatile uint32_t shootdown_generation;
static volatile uint32_t shootdown_kind;
static volatile uint32_t shootdown_vaddr;
static volatile uint32_t shootdown_asid;
static volatile uint32_t shootdown_cpu_ack[ARMOS_MAX_CPUS];

static bool tlb_request_is_kernel_scope(tlb_request_kind_t kind, uint32_t asid)
{
    if (kind == TLB_REQ_ALL)
        return true;
    if ((kind == TLB_REQ_ASID || kind == TLB_REQ_PAGE_ASID) &&
        ((asid & ASID_MASK) == ASID_KERNEL))
        return true;
    return false;
}

static uint32_t tlb_remote_target_mask(tlb_request_kind_t kind, uint32_t asid)
{
    uint32_t mask = 0;
    uint32_t boot_cpu = smp_boot_cpu_id();
    uint32_t possible = smp_possible_cpu_count();
    bool kernel_scope = tlb_request_is_kernel_scope(kind, asid);

    for (uint32_t cpu = 0; cpu < possible && cpu < ARMOS_MAX_CPUS; cpu++) {
        smp_cpu_state_t state;

        if (cpu == boot_cpu)
            continue;
        if (!smp_cpu_seen(cpu))
            continue;

        state = smp_cpu_state(cpu);
        /*
         * Parked CPUs run only the holding-pen kernel context. They have never
         * entered a user address space, so user-ASID invalidations do not need
         * to wake them. Keep kernel/global requests conservative.
         */
        if (kernel_scope) {
            if (state == SMP_CPU_PARKED || state == SMP_CPU_ONLINE)
                mask |= 1u << cpu;
        } else if (smp_scheduler_cpu_enabled(cpu)) {
            mask |= 1u << cpu;
        }
    }

    return mask;
}

static void tlb_flush_local(tlb_request_kind_t kind, uint32_t vaddr, uint32_t asid)
{
    switch (kind) {
        case TLB_REQ_ALL:
            tlb_flush_all();
            break;
        case TLB_REQ_PAGE:
            tlb_flush_by_va_asid(vaddr, 0);
            break;
        case TLB_REQ_PAGE_ASID:
            tlb_flush_by_va_asid(vaddr, asid);
            break;
        case TLB_REQ_ASID:
            tlb_flush_by_asid(asid);
            break;
        case TLB_REQ_NONE:
        default:
            break;
    }
}

static void tlb_wait_remote_ack(uint32_t target_mask, uint32_t generation)
{
    uint32_t pending = target_mask;

    /*
     * This is intentionally bounded. During SMP bring-up, a missing IPI ack
     * should degrade to a diagnostic counter, not freeze the boot CPU.
     */
    for (uint32_t spin = 0; spin < 100000 && pending; spin++) {
        uint32_t acked = 0;

        for (uint32_t cpu = 0; cpu < ARMOS_MAX_CPUS; cpu++) {
            if ((pending & (1u << cpu)) && shootdown_cpu_ack[cpu] == generation)
                acked |= 1u << cpu;
        }

        pending &= ~acked;
        __asm__ volatile("nop");
    }

    if (pending) {
        shootdown_deferred_count++;
        KWARN("TLB: remote shootdown generation %u missing ack mask=0x%08x\n",
              generation, pending);
    }
}

static void tlb_shootdown_common(tlb_request_kind_t kind, uint32_t vaddr, uint32_t asid)
{
    uint32_t target_mask;
    uint32_t generation;

    shootdown_total_count++;

    tlb_flush_local(kind, vaddr, asid);

    target_mask = tlb_remote_target_mask(kind, asid);
    if (!target_mask)
        return;

    /*
     * Publish the request before sending the SGI. The current parked-CPU path
     * only has one boot CPU initiating shootdowns, so this simple global slot is
     * enough. A future scheduler-on-all-CPUs step should replace it with a
     * locked or per-CPU rendezvous object.
     */
    generation = shootdown_generation + 1;
    shootdown_vaddr = vaddr;
    shootdown_asid = asid;
    shootdown_kind = (uint32_t)kind;
    data_memory_barrier();
    shootdown_generation = generation;
    data_sync_barrier();

    shootdown_remote_count++;
    gic_send_sgi(target_mask, IRQ_SGI_TLB_SHOOTDOWN);
    tlb_wait_remote_ack(target_mask, generation);
}

void tlb_handle_remote_ipi(uint32_t cpu_id)
{
    uint32_t generation;
    tlb_request_kind_t kind;
    uint32_t vaddr;
    uint32_t asid;

    if (cpu_id >= ARMOS_MAX_CPUS)
        return;

    generation = shootdown_generation;
    if (generation == 0 || shootdown_cpu_ack[cpu_id] == generation)
        return;

    data_memory_barrier();
    kind = (tlb_request_kind_t)shootdown_kind;
    vaddr = shootdown_vaddr;
    asid = shootdown_asid;

    tlb_flush_local(kind, vaddr, asid);
    data_sync_barrier();
    shootdown_cpu_ack[cpu_id] = generation;
    data_memory_barrier();
}

uint32_t tlb_shootdown_generation(void)
{
    return shootdown_generation;
}

uint32_t tlb_shootdown_cpu_ack(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return 0;
    return shootdown_cpu_ack[cpu_id];
}

void tlb_shootdown_all(void)
{
    tlb_shootdown_common(TLB_REQ_ALL, 0, 0);
}

void tlb_shootdown_page(uint32_t vaddr)
{
    tlb_shootdown_common(TLB_REQ_PAGE, vaddr, 0);
}

void tlb_shootdown_page_asid(uint32_t vaddr, uint32_t asid)
{
    tlb_shootdown_common(TLB_REQ_PAGE_ASID, vaddr, asid);
}

void tlb_shootdown_asid(uint32_t asid)
{
    tlb_shootdown_common(TLB_REQ_ASID, 0, asid);
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

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/smp/smp.c
 * Layer: ARM64 / SMP mechanisms
 *
 * Responsibilities:
 * - Discover CPU topology from the firmware device tree.
 * - Release QEMU CPUs through PSCI and eager Raspberry Pi cores through the
 *   architecture holding pen.
 * - Publish per-CPU lifecycle state to the common scheduler contract.
 *
 * Notes:
 * - Scheduling, idle-task creation and shutdown policy remain in common code.
 * - Secondary CPUs initialize only local architectural state before waiting
 *   for the common scheduler to authorize task execution.
 */

#include <asm/mmu.h>
#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/fdt.h>
#include <kernel/interrupt.h>
#include <kernel/memory.h>
#include <kernel/smp.h>
#include <kernel/task.h>
#include <kernel/timer.h>

#define MPIDR_AFF0_MASK          0xffULL
#define PSCI_0_2_FN64_CPU_ON     0xC4000003ULL
#define SMP_BOOT_GATE_HOLD       0x484F4C44434F5245ULL

volatile uint64_t smp_boot_gate = SMP_BOOT_GATE_HOLD;
volatile uint64_t smp_secondary_release_entry[ARMOS_MAX_CPUS];

static volatile smp_cpu_info_t cpu_info[ARMOS_MAX_CPUS];
static volatile uint32_t seen_mask;
static volatile uint32_t online_mask;
static volatile uint32_t scheduler_mask;
static volatile uint32_t scheduler_banned_mask;
static volatile uint32_t shutdown_park_mask;
static volatile uint32_t online_count;
static volatile uint32_t scheduler_reject_count;
static uint32_t boot_cpu_id;
static uint32_t possible_count;

extern void smp_secondary_entry(void);

static uint32_t atomic_load_u32(volatile uint32_t *value)
{
    uint32_t result;

    __asm__ volatile("ldar %w0, [%1]" : "=r"(result) : "r"(value) : "memory");
    return result;
}

static void atomic_or_u32(volatile uint32_t *value, uint32_t bits)
{
    uint32_t old_value;
    uint32_t new_value;
    uint32_t failed;

    do {
        __asm__ volatile(
            "ldaxr %w0, [%3]\n"
            "orr %w1, %w0, %w4\n"
            "stlxr %w2, %w1, [%3]"
            : "=&r"(old_value), "=&r"(new_value), "=&r"(failed)
            : "r"(value), "r"(bits)
            : "memory");
    } while (failed != 0);
}

static void atomic_and_u32(volatile uint32_t *value, uint32_t bits)
{
    uint32_t old_value;
    uint32_t new_value;
    uint32_t failed;

    do {
        __asm__ volatile(
            "ldaxr %w0, [%3]\n"
            "and %w1, %w0, %w4\n"
            "stlxr %w2, %w1, [%3]"
            : "=&r"(old_value), "=&r"(new_value), "=&r"(failed)
            : "r"(value), "r"(bits)
            : "memory");
    } while (failed != 0);
}

static void atomic_increment_u32(volatile uint32_t *value)
{
    uint32_t old_value;
    uint32_t new_value;
    uint32_t failed;

    do {
        __asm__ volatile(
            "ldaxr %w0, [%3]\n"
            "add %w1, %w0, #1\n"
            "stlxr %w2, %w1, [%3]"
            : "=&r"(old_value), "=&r"(new_value), "=&r"(failed)
            : "r"(value)
            : "memory");
    } while (failed != 0);
}

static void atomic_decrement_u32(volatile uint32_t *value)
{
    uint32_t old_value;
    uint32_t new_value;
    uint32_t failed;

    do {
        __asm__ volatile(
            "ldaxr %w0, [%3]\n"
            "cbz %w0, 1f\n"
            "sub %w1, %w0, #1\n"
            "stlxr %w2, %w1, [%3]\n"
            "b 2f\n"
            "1: mov %w1, %w0\n"
            "mov %w2, wzr\n"
            "2:"
            : "=&r"(old_value), "=&r"(new_value), "=&r"(failed)
            : "r"(value)
            : "memory");
    } while (failed != 0);
}

static int32_t psci_cpu_on(uint64_t target_cpu, uint64_t entry,
                           uint64_t context)
{
    register uint64_t x0 __asm__("x0") = PSCI_0_2_FN64_CPU_ON;
    register uint64_t x1 __asm__("x1") = target_cpu;
    register uint64_t x2 __asm__("x2") = entry;
    register uint64_t x3 __asm__("x3") = context;

    __asm__ volatile("hvc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return (int32_t)x0;
}

static uint32_t detect_possible_cpus(void)
{
    uint32_t count = fdt_count_cpus((void *)(uintptr_t)dtb_address,
                                    ARMOS_MAX_CPUS);

    if (count == 0)
        count = arch_platform_default_cpu_count();
    if (count == 0)
        count = 1;
    if (count > ARMOS_MAX_CPUS)
        count = ARMOS_MAX_CPUS;
    return count;
}

uint32_t smp_processor_id(void)
{
    uint64_t mpidr;

    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return (uint32_t)(mpidr & MPIDR_AFF0_MASK);
}

void smp_init_boot_cpu(void)
{
    uint32_t cpu;
    uint32_t bit;

    boot_cpu_id = smp_processor_id();
    possible_count = detect_possible_cpus();
    bit = 1u << boot_cpu_id;
    seen_mask = bit;
    online_mask = bit;
    scheduler_mask = bit;
    scheduler_banned_mask = 0;
    shutdown_park_mask = 0;
    online_count = 1;
    scheduler_reject_count = 0;

    for (cpu = 0; cpu < ARMOS_MAX_CPUS; cpu++) {
        cpu_info[cpu].cpu_id = cpu;
        cpu_info[cpu].state = cpu == boot_cpu_id ?
            SMP_CPU_ONLINE : SMP_CPU_OFFLINE;
        cpu_info[cpu].irq_count = 0;
        cpu_info[cpu].ipi_count = 0;
        cpu_info[cpu].park_heartbeat = 0;
        cpu_info[cpu].start_result = cpu == boot_cpu_id ? 0 : -ENOSYS;
        smp_secondary_release_entry[cpu] = 0;
    }
    arch_data_sync_barrier();
}

void smp_start_secondary_cpus(void)
{
    uint64_t entry = (uint64_t)(uintptr_t)smp_secondary_entry;
    uint32_t cpu;

    for (cpu = 0; cpu < possible_count; cpu++) {
        if (cpu == boot_cpu_id)
            continue;

        cpu_info[cpu].state = SMP_CPU_BOOTING;
        smp_secondary_release_entry[cpu] = entry;
        arch_clean_dcache_by_mva(
            (const void *)&smp_secondary_release_entry[cpu],
            sizeof(smp_secondary_release_entry[cpu]));
        if (arch_platform_has_psci())
            cpu_info[cpu].start_result = psci_cpu_on(cpu, entry, cpu);
        else
            cpu_info[cpu].start_result = 0;

        if (cpu_info[cpu].start_result != 0)
            cpu_info[cpu].state = SMP_CPU_OFFLINE;
    }
    arch_data_sync_barrier();
    __asm__ volatile("sev" ::: "memory");
}

void smp_secondary_main(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS)
        cpu_id = smp_processor_id();
    if (cpu_id >= ARMOS_MAX_CPUS)
        for (;;)
            arch_wait_for_interrupt();

    bit = 1u << cpu_id;
    atomic_or_u32(&seen_mask, bit);
    cpu_info[cpu_id].state = SMP_CPU_PARKED;
    cpu_info[cpu_id].start_result = 0;
    arch_data_sync_barrier();

    irq_init_local_cpu_interface();
    timer_init_local_cpu();
    irq_enable_level(arch_platform_timer_irq());
    arch_enable_interrupts();

    for (;;) {
        cpu_info[cpu_id].park_heartbeat++;
        if (smp_scheduler_cpu_enabled(cpu_id))
            task_start_secondary_scheduler(cpu_id);
        arch_wait_for_interrupt();
    }
}

uint32_t smp_boot_cpu_id(void) { return boot_cpu_id; }
uint32_t smp_seen_cpu_mask(void) { return atomic_load_u32(&seen_mask); }
uint32_t smp_online_cpu_count(void) { return atomic_load_u32(&online_count); }
uint32_t smp_possible_cpu_count(void) { return possible_count; }

int32_t smp_cpu_start_result(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS ? cpu_info[cpu_id].start_result : -EINVAL;
}

uint32_t smp_cpu_release_entry(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS ?
        (uint32_t)smp_secondary_release_entry[cpu_id] : 0;
}

uint32_t smp_cpu_release_mailbox3_value(uint32_t cpu_id)
{
    (void)cpu_id;
    return 0;
}

uint32_t smp_cpu_release_spin_table_value(uint32_t cpu_id)
{
    (void)cpu_id;
    return 0;
}

smp_cpu_state_t smp_cpu_state(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS ?
        (smp_cpu_state_t)cpu_info[cpu_id].state : SMP_CPU_OFFLINE;
}

const char *smp_cpu_state_name(uint32_t cpu_id)
{
    switch (smp_cpu_state(cpu_id)) {
    case SMP_CPU_BOOTING: return "booting";
    case SMP_CPU_PARKED: return "parked";
    case SMP_CPU_ONLINE: return "online";
    default: return "offline";
    }
}

const smp_cpu_info_t *smp_cpu_info(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS ?
        (const smp_cpu_info_t *)&cpu_info[cpu_id] : NULL;
}

void smp_note_irq(uint32_t cpu_id)
{
    if (cpu_id < ARMOS_MAX_CPUS)
        cpu_info[cpu_id].irq_count++;
}

void smp_note_ipi(uint32_t cpu_id)
{
    if (cpu_id < ARMOS_MAX_CPUS)
        cpu_info[cpu_id].ipi_count++;
}

bool smp_is_boot_cpu(void) { return smp_processor_id() == boot_cpu_id; }

bool smp_cpu_seen(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS &&
        (atomic_load_u32(&seen_mask) & (1u << cpu_id)) != 0;
}

bool smp_cpu_online(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS &&
        (atomic_load_u32(&online_mask) & (1u << cpu_id)) != 0;
}

uint32_t smp_scheduler_cpu_mask(void)
{
    return atomic_load_u32(&scheduler_mask);
}

int smp_enable_scheduler_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id ||
        !smp_cpu_seen(cpu_id) || smp_cpu_state(cpu_id) != SMP_CPU_PARKED ||
        !task_idle_on_cpu(cpu_id))
        return -1;
    bit = 1u << cpu_id;
    if (atomic_load_u32(&scheduler_banned_mask) & bit)
        return -1;

    if ((atomic_load_u32(&online_mask) & bit) == 0) {
        atomic_or_u32(&online_mask, bit);
        atomic_increment_u32(&online_count);
    }
    atomic_or_u32(&scheduler_mask, bit);
    cpu_info[cpu_id].state = SMP_CPU_ONLINE;
    arch_data_sync_barrier();
    __asm__ volatile("sev" ::: "memory");
    return 0;
}

void smp_disable_scheduler_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return;
    bit = 1u << cpu_id;
    atomic_or_u32(&scheduler_banned_mask, bit);
    atomic_and_u32(&scheduler_mask, ~bit);
    arch_data_sync_barrier();
}

bool smp_scheduler_cpu_enabled(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS)
        return false;
    bit = 1u << cpu_id;
    return (atomic_load_u32(&scheduler_mask) & bit) != 0 &&
           (atomic_load_u32(&online_mask) & bit) != 0;
}

bool smp_scheduler_can_run_on_current_cpu(void)
{
    if (smp_scheduler_cpu_enabled(smp_processor_id()))
        return true;
    atomic_increment_u32(&scheduler_reject_count);
    return false;
}

uint32_t smp_scheduler_reject_count(void)
{
    return atomic_load_u32(&scheduler_reject_count);
}

void smp_request_shutdown_park_secondary_cpus(void)
{
    uint32_t cpu;

    for (cpu = 0; cpu < possible_count; cpu++) {
        if (cpu != boot_cpu_id && smp_cpu_state(cpu) == SMP_CPU_ONLINE)
            atomic_or_u32(&shutdown_park_mask, 1u << cpu);
    }
    arch_data_sync_barrier();
    __asm__ volatile("sev" ::: "memory");
}

bool smp_shutdown_park_requested(uint32_t cpu_id)
{
    return cpu_id < ARMOS_MAX_CPUS && cpu_id != boot_cpu_id &&
        (atomic_load_u32(&shutdown_park_mask) & (1u << cpu_id)) != 0;
}

void smp_mark_shutdown_parked_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return;
    bit = 1u << cpu_id;
    atomic_and_u32(&scheduler_mask, ~bit);
    atomic_or_u32(&scheduler_banned_mask, bit);
    atomic_and_u32(&shutdown_park_mask, ~bit);
    if (atomic_load_u32(&online_mask) & bit) {
        atomic_and_u32(&online_mask, ~bit);
        atomic_decrement_u32(&online_count);
    }
    cpu_info[cpu_id].state = SMP_CPU_PARKED;
    arch_data_sync_barrier();
}

bool smp_shutdown_secondary_cpus_parked(void)
{
    uint32_t cpu;

    for (cpu = 0; cpu < possible_count; cpu++) {
        if (cpu == boot_cpu_id || !smp_cpu_seen(cpu))
            continue;
        if (smp_shutdown_park_requested(cpu) ||
            smp_cpu_state(cpu) == SMP_CPU_ONLINE)
            return false;
    }
    return true;
}

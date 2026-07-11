/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/smp/smp.c
 * Layer: ARM32 / SMP coordination
 *
 * Responsibilities:
 * - Discover possible CPUs from the DTB.
 * - Start secondary CPUs through PSCI or the active board release mechanism.
 * - Track boot, seen, online and scheduler-enabled CPU masks.
 * - Provide common CPU-id helpers for locks and diagnostics.
 *
 * Notes:
 * - Secondary CPUs are brought into C, given private exception stacks, then
 *   parked outside the scheduler. Once TLB shootdown and per-CPU timers are
 *   ready, smp_enable_scheduler_cpu() admits them into normal scheduling.
 */

#include <kernel/smp.h>
#include <kernel/fdt.h>
#include <kernel/memory.h>
#include <kernel/stddef.h>
#include <kernel/string.h>
#include <kernel/interrupt.h>
#include <kernel/task.h>
#include <kernel/timer.h>
#include <kernel/arch_platform.h>
#include <kernel/arch_cpu.h>
#include <asm/arm.h>

#define PSCI_0_2_FN_CPU_ON 0x84000003u

#if defined(ARMOS_PLATFORM_RASPBERRYPI)
#define RASPI2_LOCAL_MAILBOX3_SET0      0x08Cu
#define RASPI2_LOCAL_MAILBOX3_CLEAR0    0x0CCu
#define RASPI2_LOCAL_MAILBOX_STRIDE     0x010u
#define RASPI2_SECONDARY_BOOT_TIMEOUT_MS 1000u
#define RASPI3_SPIN_TABLE_BASE          0x0D8u
#define RASPI3_SPIN_TABLE_STRIDE        0x008u
#endif

_Static_assert(sizeof(smp_cpu_info_t) == 24,
               "smp_cpu_info_t size must match boot.S");
_Static_assert(offsetof(smp_cpu_info_t, state) == 4,
               "smp_cpu_info_t.state offset must match boot.S");
_Static_assert(offsetof(smp_cpu_info_t, park_heartbeat) == 16,
               "smp_cpu_info_t.park_heartbeat offset must match boot.S");

volatile uint32_t smp_seen_mask = 1u << ARMOS_BOOT_CPU;
volatile uint32_t smp_secondary_release_entry[ARMOS_MAX_CPUS];
static volatile uint32_t smp_release_mailbox3_value[ARMOS_MAX_CPUS];
static volatile uint32_t smp_release_spin_table_value[ARMOS_MAX_CPUS];
volatile smp_cpu_info_t smp_cpu_infos[ARMOS_MAX_CPUS] = {
    [ARMOS_BOOT_CPU] = {
        .cpu_id = ARMOS_BOOT_CPU,
        .state = SMP_CPU_ONLINE,
        .start_result = 0,
    },
};

static uint32_t boot_cpu_id = ARMOS_BOOT_CPU;
static uint32_t online_cpu_mask = 1u << ARMOS_BOOT_CPU;
static volatile uint32_t scheduler_cpu_mask = 1u << ARMOS_BOOT_CPU;
static volatile uint32_t scheduler_banned_mask;
static uint32_t possible_cpu_count = 1;
static volatile uint32_t online_cpu_count = 1;
static volatile uint32_t scheduler_reject_count;
static volatile uint32_t scheduler_shutdown_park_request_mask;

extern void smp_secondary_entry(void);

static void smp_seen_mask_or(uint32_t bit)
{
    uint32_t old_value;
    uint32_t new_value;
    uint32_t status;

    do {
        __asm__ volatile(
            "ldrex  %0, [%3]\n"
            "orr    %1, %0, %4\n"
            "strex  %2, %1, [%3]\n"
            : "=&r"(old_value), "=&r"(new_value), "=&r"(status)
            : "r"(&smp_seen_mask), "r"(bit)
            : "cc", "memory");
    } while (status != 0);

    data_memory_barrier();
}

static void smp_mark_secondary_parked(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return;

    smp_seen_mask_or(1u << cpu_id);
    if (!smp_scheduler_cpu_enabled(cpu_id))
        smp_cpu_infos[cpu_id].state = SMP_CPU_PARKED;
}

#if defined(ARMOS_PLATFORM_RASPBERRYPI)
static inline volatile uint32_t* raspi2_smp_local_base(void)
{
    if (!arch_mmu_enabled())
        return (volatile uint32_t*)(uintptr_t)arch_platform_irqctrl_phys_start();
    return (volatile uint32_t*)(uintptr_t)arch_platform_kernel_mmio_irqctrl_base();
}

static inline void raspi2_smp_local_write(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t*)((volatile uint8_t*)raspi2_smp_local_base() + offset) = value;
    data_sync_barrier();
}

static inline uint32_t raspi2_smp_local_read(uint32_t offset)
{
    uint32_t value;

    value = *(volatile uint32_t*)((volatile uint8_t*)raspi2_smp_local_base() + offset);
    data_sync_barrier();
    return value;
}

static void raspi2_smp_write_spin_table(uint32_t cpu, uint32_t entry_point)
{
    volatile uint32_t* release;
    uintptr_t release_addr;

    if (cpu >= 4)
        return;

    release_addr = RASPI3_SPIN_TABLE_BASE + RASPI3_SPIN_TABLE_STRIDE * cpu;
    release = (volatile uint32_t*)release_addr;
    release[0] = entry_point;
    release[1] = 0;
    smp_release_spin_table_value[cpu] = entry_point;
    clean_dcache_by_mva((const void*)release_addr, sizeof(uint32_t) * 2u);
    data_sync_barrier();
}

static int32_t smp_raspi2_cpu_on(uint32_t cpu, uint32_t entry_point)
{
    uint64_t start;
    uint64_t timeout_ticks;

    if (cpu >= ARMOS_MAX_CPUS || cpu >= 4)
        return -EINVAL;

    smp_cpu_infos[cpu].state = SMP_CPU_BOOTING;
    smp_secondary_release_entry[cpu] = entry_point;
    smp_release_mailbox3_value[cpu] = 0xffffffffu;
    smp_release_spin_table_value[cpu] = 0;
    clean_dcache_by_mva((const void*)&smp_secondary_release_entry[cpu],
                        sizeof(smp_secondary_release_entry[cpu]));
    raspi2_smp_write_spin_table(cpu, entry_point);
    data_sync_barrier();

    /*
     * BCM2836/BCM2837 firmware waits on mailbox 3 for secondary start
     * addresses. Cores that were entered eagerly by an emulator instead watch
     * smp_secondary_release_entry[] in boot.S; SEV wakes both paths.
     */
    raspi2_smp_local_write(RASPI2_LOCAL_MAILBOX3_CLEAR0 +
                           RASPI2_LOCAL_MAILBOX_STRIDE * cpu,
                           0xffffffffu);
    raspi2_smp_local_write(RASPI2_LOCAL_MAILBOX3_SET0 +
                           RASPI2_LOCAL_MAILBOX_STRIDE * cpu,
                           entry_point);
    send_event();
    instruction_sync_barrier();

    start = get_timer_count();
    timeout_ticks = (uint64_t)(get_timer_frequency() / 1000u) *
                    RASPI2_SECONDARY_BOOT_TIMEOUT_MS;
    if (timeout_ticks == 0)
        timeout_ticks = 1;

    while ((get_timer_count() - start) < timeout_ticks) {
        smp_release_mailbox3_value[cpu] =
            raspi2_smp_local_read(RASPI2_LOCAL_MAILBOX3_CLEAR0 +
                                  RASPI2_LOCAL_MAILBOX_STRIDE * cpu);
        if (smp_cpu_seen(cpu) && smp_cpu_state(cpu) == SMP_CPU_PARKED)
            return 0;
        cpu_relax();
    }

    return -ETIMEDOUT;
}
#endif

static bool smp_platform_can_start_secondary_cpus(void)
{
#if defined(ARMOS_PLATFORM_RASPBERRYPI)
    return true;
#else
    return false;
#endif
}

static int32_t smp_platform_cpu_on(uint32_t target_cpu,
                                   uint32_t entry_point,
                                   uint32_t context_id)
{
    (void)context_id;

#if defined(ARMOS_PLATFORM_RASPBERRYPI)
    return smp_raspi2_cpu_on(target_cpu, entry_point);
#else
    (void)target_cpu;
    (void)entry_point;
    return -ENOSYS;
#endif
}

static uint32_t smp_detect_possible_cpus_from_dtb(void)
{
    void* dtb_ptr = (void*)dtb_address;
    uint32_t count = 0;
    uint32_t fallback = arch_platform_default_cpu_count();

    if (!dtb_ptr)
        return fallback ? fallback : 1;

    if (!fdt_check_header(dtb_ptr))
        return fallback ? fallback : 1;

    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    uint8_t* struct_block = (uint8_t*)dtb_ptr + fdt32_to_cpu(fdt->off_dt_struct);
    uint32_t* token = (uint32_t*)struct_block;

    while (1) {
        uint32_t tag = fdt32_to_cpu(*token++);

        switch (tag) {
            case FDT_BEGIN_NODE: {
                const char* name = (const char*)token;
                size_t len = strlen(name);

                if (fdt_node_matches(name, "cpu") && count < ARMOS_MAX_CPUS)
                    count++;

                token += (len + 4) / 4;
                break;
            }
            case FDT_PROP: {
                uint32_t len = fdt32_to_cpu(*token++);
                token++;
                token += (len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
            case FDT_NOP:
                break;
            case FDT_END:
                return count ? count : (fallback ? fallback : 1);
            default:
                return count ? count : (fallback ? fallback : 1);
        }
    }
}

static int32_t smp_psci_cpu_on(uint32_t target_cpu, uint32_t entry_point, uint32_t context_id)
{
    return (int32_t)arm_hvc_call(PSCI_0_2_FN_CPU_ON, target_cpu, entry_point, context_id);
}

void smp_init_boot_cpu(void)
{
    boot_cpu_id = get_cpu_id();
    smp_seen_mask |= 1u << boot_cpu_id;
    online_cpu_mask = 1u << boot_cpu_id;
    scheduler_cpu_mask = 1u << boot_cpu_id;
    online_cpu_count = 1;
    possible_cpu_count = smp_detect_possible_cpus_from_dtb();
    if (possible_cpu_count > ARMOS_MAX_CPUS)
        possible_cpu_count = ARMOS_MAX_CPUS;

    for (uint32_t cpu = 0; cpu < ARMOS_MAX_CPUS; cpu++) {
        smp_cpu_infos[cpu].cpu_id = cpu;
        smp_cpu_infos[cpu].state = (cpu == boot_cpu_id) ? SMP_CPU_ONLINE : SMP_CPU_OFFLINE;
        smp_cpu_infos[cpu].irq_count = 0;
        smp_cpu_infos[cpu].ipi_count = 0;
        smp_cpu_infos[cpu].park_heartbeat = 0;
        smp_cpu_infos[cpu].start_result = (cpu == boot_cpu_id) ? 0 : 1;
        smp_secondary_release_entry[cpu] = 0;
    }
}

void smp_start_secondary_cpus(void)
{
    uint32_t entry = (uint32_t)smp_secondary_entry;

    if (!arch_platform_has_psci()) {
        if (smp_platform_can_start_secondary_cpus()) {
            for (uint32_t cpu = 0; cpu < possible_cpu_count; cpu++) {
                if (cpu == boot_cpu_id)
                    continue;

                smp_cpu_infos[cpu].start_result =
                    smp_platform_cpu_on(cpu, entry, cpu);
                if (smp_cpu_infos[cpu].start_result != 0)
                    smp_cpu_infos[cpu].state = SMP_CPU_OFFLINE;
            }

            data_sync_barrier();
            send_event();
            instruction_sync_barrier();
            return;
        }

        for (uint32_t cpu = 0; cpu < possible_cpu_count; cpu++) {
            if (cpu == boot_cpu_id)
                continue;
            smp_cpu_infos[cpu].state = SMP_CPU_OFFLINE;
            smp_cpu_infos[cpu].start_result = -ENOSYS;
        }
        return;
    }

    for (uint32_t cpu = 0; cpu < possible_cpu_count; cpu++) {
        if (cpu == boot_cpu_id)
            continue;

        /*
         * QEMU virt exposes linear MPIDR affinity values for Cortex-A15 CPUs.
         * The secondary entry only parks the CPU; it must not join scheduler
         * state until TLB shootdown and per-CPU interrupt setup exist.
         */
        smp_cpu_infos[cpu].state = SMP_CPU_BOOTING;
        smp_cpu_infos[cpu].start_result = smp_psci_cpu_on(cpu, entry, cpu);
        if (smp_cpu_infos[cpu].start_result != 0)
            smp_cpu_infos[cpu].state = SMP_CPU_OFFLINE;
    }

    data_sync_barrier();
    send_event();
    instruction_sync_barrier();
}

void smp_secondary_main(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        cpu_id = smp_processor_id();

    smp_mark_secondary_parked(cpu_id);

    irq_init_local_cpu_interface();
    timer_init_local_cpu();
    enable_interrupts();

    while (1) {
        if (cpu_id < ARMOS_MAX_CPUS) {
            smp_mark_secondary_parked(cpu_id);
            smp_cpu_infos[cpu_id].park_heartbeat++;
        }

        if (cpu_id < ARMOS_MAX_CPUS && smp_scheduler_cpu_enabled(cpu_id))
            task_start_secondary_scheduler(cpu_id);

        /*
         * The secondary CPU is alive in C, but still outside the scheduler.
         * Only diagnostic SGIs are enabled here. It must not run tasks or handle
         * device interrupts until the scheduler and per-CPU timer path are SMP
         * aware. WFI avoids the old busy WFE heartbeat storm.
         */
        data_sync_barrier();
        wait_for_interrupt();
    }
}

uint32_t smp_processor_id(void)
{
    return get_cpu_id();
}

uint32_t smp_boot_cpu_id(void)
{
    return boot_cpu_id;
}

uint32_t smp_seen_cpu_mask(void)
{
    return smp_seen_mask;
}

uint32_t smp_online_cpu_count(void)
{
    return online_cpu_count;
}

uint32_t smp_possible_cpu_count(void)
{
    return possible_cpu_count;
}

int32_t smp_cpu_start_result(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return -1;
    return smp_cpu_infos[cpu_id].start_result;
}

uint32_t smp_cpu_release_entry(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return 0;
    return smp_secondary_release_entry[cpu_id];
}

uint32_t smp_cpu_release_mailbox3_value(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return 0;
    return smp_release_mailbox3_value[cpu_id];
}

uint32_t smp_cpu_release_spin_table_value(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return 0;
    return smp_release_spin_table_value[cpu_id];
}

smp_cpu_state_t smp_cpu_state(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return SMP_CPU_OFFLINE;
    return (smp_cpu_state_t)smp_cpu_infos[cpu_id].state;
}

const char* smp_cpu_state_name(uint32_t cpu_id)
{
    switch (smp_cpu_state(cpu_id)) {
        case SMP_CPU_ONLINE:
            return "online";
        case SMP_CPU_PARKED:
            return "parked";
        case SMP_CPU_BOOTING:
            return "booting";
        case SMP_CPU_OFFLINE:
        default:
            return "offline";
    }
}

const smp_cpu_info_t* smp_cpu_info(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return NULL;
    return (const smp_cpu_info_t*)&smp_cpu_infos[cpu_id];
}

void smp_note_irq(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return;
    smp_cpu_infos[cpu_id].irq_count++;
}

void smp_note_ipi(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return;
    smp_cpu_infos[cpu_id].ipi_count++;
}

bool smp_is_boot_cpu(void)
{
    return smp_processor_id() == boot_cpu_id;
}

bool smp_cpu_seen(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return false;
    return (smp_seen_mask & (1u << cpu_id)) != 0;
}

bool smp_cpu_online(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return false;
    return (online_cpu_mask & (1u << cpu_id)) != 0;
}

uint32_t smp_scheduler_cpu_mask(void)
{
    return scheduler_cpu_mask;
}

int smp_enable_scheduler_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return -1;

    if (scheduler_banned_mask & (1u << cpu_id))
        return -1;

    if (!smp_cpu_seen(cpu_id) || smp_cpu_state(cpu_id) != SMP_CPU_PARKED)
        return -1;

    if (!task_idle_on_cpu(cpu_id))
        return -1;

    bit = 1u << cpu_id;
    if ((online_cpu_mask & bit) == 0) {
        online_cpu_mask |= bit;
        online_cpu_count++;
    }

    scheduler_cpu_mask |= bit;
    smp_cpu_infos[cpu_id].state = SMP_CPU_ONLINE;
    data_sync_barrier();
    send_event();
    return 0;
}

void smp_disable_scheduler_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return;

    bit = 1u << cpu_id;
    scheduler_banned_mask |= bit;
    scheduler_cpu_mask &= ~bit;
    data_sync_barrier();
}

void smp_request_shutdown_park_secondary_cpus(void)
{
    for (uint32_t cpu = 0; cpu < possible_cpu_count && cpu < ARMOS_MAX_CPUS; cpu++) {
        uint32_t bit;

        if (cpu == boot_cpu_id)
            continue;

        bit = 1u << cpu;

        /*
         * Do not disable scheduler participation here.  A secondary CPU may
         * still be running a normal task when shutdown starts; it needs one
         * more legal scheduler path to return to its idle task, where the park
         * request is consumed.  The CPU is removed from scheduler_cpu_mask only
         * after smp_mark_shutdown_parked_cpu().
         */
        if (smp_cpu_seen(cpu) && smp_cpu_infos[cpu].state == SMP_CPU_ONLINE)
            scheduler_shutdown_park_request_mask |= bit;
    }

    data_sync_barrier();
    send_event();
}

bool smp_shutdown_park_requested(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return false;

    return (scheduler_shutdown_park_request_mask & (1u << cpu_id)) != 0;
}

void smp_mark_shutdown_parked_cpu(uint32_t cpu_id)
{
    uint32_t bit;

    if (cpu_id >= ARMOS_MAX_CPUS || cpu_id == boot_cpu_id)
        return;

    bit = 1u << cpu_id;
    scheduler_cpu_mask &= ~bit;
    scheduler_banned_mask |= bit;
    scheduler_shutdown_park_request_mask &= ~bit;

    if (online_cpu_mask & bit) {
        online_cpu_mask &= ~bit;
        if (online_cpu_count > 0)
            online_cpu_count--;
    }

    smp_cpu_infos[cpu_id].state = SMP_CPU_PARKED;
    data_sync_barrier();
}

bool smp_shutdown_secondary_cpus_parked(void)
{
    for (uint32_t cpu = 0; cpu < possible_cpu_count && cpu < ARMOS_MAX_CPUS; cpu++) {
        if (cpu == boot_cpu_id)
            continue;
        if (!smp_cpu_seen(cpu))
            continue;
        if (scheduler_shutdown_park_request_mask & (1u << cpu))
            return false;
        if (smp_cpu_infos[cpu].state == SMP_CPU_ONLINE)
            return false;
    }

    return true;
}

bool smp_scheduler_cpu_enabled(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return false;

    return (scheduler_cpu_mask & (1u << cpu_id)) != 0 &&
           smp_cpu_online(cpu_id);
}

bool smp_scheduler_can_run_on_current_cpu(void)
{
    if (smp_scheduler_cpu_enabled(smp_processor_id()))
        return true;

    /*
     * Secondary CPUs are intentionally parked during this bring-up phase.
     * If this counter ever moves, some path released a CPU before per-CPU
     * scheduler state and remote TLB shootdown are safe.
     */
    scheduler_reject_count++;
    return false;
}

uint32_t smp_scheduler_reject_count(void)
{
    return scheduler_reject_count;
}

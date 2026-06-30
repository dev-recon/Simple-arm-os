/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/smp.c
 * Layer: Kernel / SMP coordination
 *
 * Responsibilities:
 * - Track the boot CPU and online CPU count.
 * - Provide common CPU-id helpers for locks and diagnostics.
 *
 * Notes:
 * - Secondary CPU startup is intentionally not implemented in this step.
 *   Keeping this module passive lets us make the kernel SMP-aware without
 *   changing runtime behaviour on QEMU -smp 1.
 */

#include <kernel/smp.h>
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <asm/arm.h>

#define PSCI_0_2_FN_CPU_ON 0x84000003u

volatile uint32_t smp_seen_mask = 1u << ARMOS_BOOT_CPU;

static uint32_t boot_cpu_id = ARMOS_BOOT_CPU;
static uint32_t online_cpu_mask = 1u << ARMOS_BOOT_CPU;
static uint32_t possible_cpu_count = 1;
static volatile uint32_t online_cpu_count = 1;
static int32_t cpu_start_result[ARMOS_MAX_CPUS];

extern void smp_secondary_entry(void);

static inline uint32_t smp_fdt32_to_cpu(uint32_t value)
{
    return __builtin_bswap32(value);
}

static uint32_t smp_detect_possible_cpus_from_dtb(void)
{
    void* dtb_ptr = (void*)dtb_address;
    uint32_t count = 0;

    if (!dtb_ptr)
        return 1;

    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    if (smp_fdt32_to_cpu(fdt->magic) != FDT_MAGIC)
        return 1;

    uint8_t* struct_block = (uint8_t*)dtb_ptr + smp_fdt32_to_cpu(fdt->off_dt_struct);
    uint32_t* token = (uint32_t*)struct_block;

    while (1) {
        uint32_t tag = smp_fdt32_to_cpu(*token++);

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
                uint32_t len = smp_fdt32_to_cpu(*token++);
                token++;
                token += (len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
            case FDT_NOP:
                break;
            case FDT_END:
                return count ? count : 1;
            default:
                return count ? count : 1;
        }
    }
}

static int32_t smp_psci_cpu_on(uint32_t target_cpu, uint32_t entry_point, uint32_t context_id)
{
    register uint32_t function_id __asm__("r0") = PSCI_0_2_FN_CPU_ON;
    register uint32_t r1 __asm__("r1") = target_cpu;
    register uint32_t r2 __asm__("r2") = entry_point;
    register uint32_t r3 __asm__("r3") = context_id;

    __asm__ volatile("hvc #0"
                     : "+r"(function_id)
                     : "r"(r1), "r"(r2), "r"(r3)
                     : "memory");

    return (int32_t)function_id;
}

void smp_init_boot_cpu(void)
{
    boot_cpu_id = get_cpu_id();
    smp_seen_mask |= 1u << boot_cpu_id;
    online_cpu_mask = 1u << boot_cpu_id;
    online_cpu_count = 1;
    possible_cpu_count = smp_detect_possible_cpus_from_dtb();
    if (possible_cpu_count > ARMOS_MAX_CPUS)
        possible_cpu_count = ARMOS_MAX_CPUS;

    for (uint32_t cpu = 0; cpu < ARMOS_MAX_CPUS; cpu++)
        cpu_start_result[cpu] = (cpu == boot_cpu_id) ? 0 : 1;
}

void smp_start_secondary_cpus(void)
{
    uint32_t entry = (uint32_t)smp_secondary_entry;

    for (uint32_t cpu = 0; cpu < possible_cpu_count; cpu++) {
        if (cpu == boot_cpu_id)
            continue;

        /*
         * QEMU virt exposes linear MPIDR affinity values for Cortex-A15 CPUs.
         * The secondary entry only parks the CPU; it must not join scheduler
         * state until TLB shootdown and per-CPU interrupt setup exist.
         */
        cpu_start_result[cpu] = smp_psci_cpu_on(cpu, entry, cpu);
    }

    __asm__ volatile("dsb; sev; isb" ::: "memory");
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
    return cpu_start_result[cpu_id];
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

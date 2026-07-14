/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/cpu/cpu.c
 * Layer: ARM64 / CPU mechanisms
 *
 * Responsibilities:
 * - Expose local AArch64 CPU state required by the common kernel.
 * - Keep system-register accesses behind the architecture boundary.
 *
 * Notes:
 * - Platform identity and topology are supplied separately from these local
 *   architectural operations.
 */

#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/smp.h>
#include <kernel/string.h>

#define SCTLR_EL1_M (1ULL << 0)

static volatile uint32_t exception_depth[ARMOS_MAX_CPUS];

void arch_get_cpuinfo(arch_cpuinfo_t *info)
{
    uint64_t midr;
    uint64_t mpidr;

    if (!info)
        return;
    memset(info, 0, sizeof(*info));
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    info->model_name = arch_platform_cpu_model();
    info->features = arch_platform_cpu_features();
    info->hardware = arch_platform_hardware_name();
    info->implementer = (uint32_t)((midr >> 24) & 0xffu);
    info->architecture = 8;
    info->part = (uint32_t)((midr >> 4) & 0xfffu);
    info->revision = (uint32_t)(midr & 0xfu);
    info->mpidr = (uint32_t)mpidr;
}

const char *arch_machine_name(void)
{
    return "aarch64";
}

void arch_disable_interrupts(void)
{
    __asm__ volatile("msr daifset, #2\n\tisb" ::: "memory");
}

void arch_enable_interrupts(void)
{
    __asm__ volatile("msr daifclr, #2\n\tisb" ::: "memory");
}

void arch_enable_async_abort(void)
{
    __asm__ volatile("msr daifclr, #4\n\tisb" ::: "memory");
}

void arch_enable_smp_coherency(void)
{
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
}

void arch_wait_for_interrupt(void)
{
    __asm__ volatile("wfi" ::: "memory");
}

void arch_disable_branch_predictor(void)
{
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
}

uint32_t arch_timer_frequency(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return arch_platform_timer_effective_hz((uint32_t)value);
}

uint64_t arch_timer_counter(void)
{
    uint64_t value;

    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(value));
    return value;
}

bool arch_mmu_enabled(void)
{
    uint64_t sctlr;

    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    return (sctlr & SCTLR_EL1_M) != 0;
}

vaddr_t arch_current_link_register(void)
{
    uint64_t value;

    __asm__ volatile("mov %0, x30" : "=r"(value));
    return (vaddr_t)value;
}

vaddr_t arch_current_stack_pointer(void)
{
    uint64_t value;

    __asm__ volatile("mov %0, sp" : "=r"(value));
    return (vaddr_t)value;
}

void arch_set_stack_pointer(vaddr_t sp)
{
    __asm__ volatile("mov sp, %0" :: "r"((uint64_t)sp) : "memory");
}

uint32_t arch_current_mode(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, currentel" : "=r"(value));
    return (uint32_t)((value >> 2) & 0x3u);
}

bool arch_current_mode_is_interrupt(void)
{
    uint32_t cpu = smp_processor_id();

    return cpu < ARMOS_MAX_CPUS && exception_depth[cpu] != 0;
}

uint32_t arch_saved_mode(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, spsr_el1" : "=r"(value));
    return (uint32_t)(value & 0xfu);
}

uint32_t arch_saved_svc_status(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, spsr_el1" : "=r"(value));
    return (uint32_t)value;
}

bool arch_mode_is_user(uint32_t mode)
{
    return mode == 0;
}

bool arch_mode_is_supervisor(uint32_t mode)
{
    return mode == 5;
}

const char *arch_mode_name(uint32_t mode)
{
    switch (mode) {
    case 0:
        return "EL0t";
    case 4:
        return "EL1t";
    case 5:
        return "EL1h";
    default:
        return "UNKNOWN";
    }
}

void arm64_exception_depth_enter(void)
{
    uint32_t cpu = smp_processor_id();

    if (cpu < ARMOS_MAX_CPUS)
        exception_depth[cpu]++;
}

void arm64_exception_depth_leave(void)
{
    uint32_t cpu = smp_processor_id();

    if (cpu < ARMOS_MAX_CPUS && exception_depth[cpu] != 0)
        exception_depth[cpu]--;
}

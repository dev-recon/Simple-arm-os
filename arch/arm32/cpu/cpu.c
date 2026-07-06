/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/cpu/cpu.c
 * Layer: ARM32 / CPU identity
 *
 * Responsibilities:
 * - Read ARMv7 CPU identity registers for procfs and diagnostics.
 * - Keep ARM CP15 register access out of generic procfs code.
 *
 * Notes:
 * - The strings are currently calibrated for QEMU virt Cortex-A15.
 */

#include <kernel/arch_cpu.h>
#include <kernel/string.h>
#include <asm/arm.h>

void arch_get_cpuinfo(arch_cpuinfo_t* info)
{
    uint32_t midr;

    if (!info)
        return;

    memset(info, 0, sizeof(*info));

    midr = arm_read_midr();
    info->model_name = "ARM Cortex-A15 @ QEMU virt";
    info->features = "swp half thumb fastmult vfp edsp neon vfpv4 tls";
    info->hardware = "ArmOS QEMU virt";
    info->implementer = (midr >> 24) & 0xff;
    info->architecture = 7;
    info->part = (midr >> 4) & 0xfff;
    info->revision = midr & 0xf;
    info->mpidr = arm_read_mpidr();
}

void arch_disable_interrupts(void)
{
    disable_interrupts();
}

void arch_enable_interrupts(void)
{
    enable_interrupts();
}

void arch_wait_for_interrupt(void)
{
    wait_for_interrupt();
}

void arch_disable_branch_predictor(void)
{
    uint32_t sctlr;

    sctlr = get_sctlr();
    sctlr &= ~(1u << 11);
    set_sctlr(sctlr);
    flush_branch_predictor();
}

uint32_t arch_timer_frequency(void)
{
    uint32_t timer_freq = get_cntfrq();

    return timer_freq ? timer_freq : 62500000u;
}

uint64_t arch_timer_counter(void)
{
    return get_cntpct();
}

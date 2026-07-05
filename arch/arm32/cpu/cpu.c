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

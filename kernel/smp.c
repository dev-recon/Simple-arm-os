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
#include <asm/arm.h>

static uint32_t boot_cpu_id = ARMOS_BOOT_CPU;
static volatile uint32_t online_cpu_count = 1;

void smp_init_boot_cpu(void)
{
    boot_cpu_id = get_cpu_id();
    online_cpu_count = 1;
}

uint32_t smp_processor_id(void)
{
    return get_cpu_id();
}

uint32_t smp_boot_cpu_id(void)
{
    return boot_cpu_id;
}

uint32_t smp_online_cpu_count(void)
{
    return online_cpu_count;
}

bool smp_is_boot_cpu(void)
{
    return smp_processor_id() == boot_cpu_id;
}

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
 * - Report the current logical CPU from MPIDR_EL1.
 * - Provide the architecture mechanism used by common spinlock ownership.
 *
 * Notes:
 * - CPU discovery, release and scheduler policy remain outside this local
 *   register-access helper.
 */

#include <kernel/smp.h>

#define MPIDR_AFF0_MASK 0xffULL

uint32_t smp_processor_id(void)
{
    uint64_t mpidr;

    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return (uint32_t)(mpidr & MPIDR_AFF0_MASK);
}

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

#define SCTLR_EL1_M (1ULL << 0)

bool arch_mmu_enabled(void)
{
    uint64_t sctlr;

    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    return (sctlr & SCTLR_EL1_M) != 0;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_mmu_debug.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose a stable snapshot of architecture translation registers.
 * - Keep procfs independent from ARM32 CP15 and AArch64 system-register
 *   encodings.
 *
 * Notes:
 * - Values are diagnostic only and must not be used to control the MMU.
 */

#ifndef _KERNEL_ARCH_MMU_DEBUG_H
#define _KERNEL_ARCH_MMU_DEBUG_H

#include <kernel/types.h>

typedef struct arch_mmu_debug_state {
    uint64_t control;
    uint64_t auxiliary;
    uint64_t root0;
    uint64_t root1;
    uint64_t translation_control;
    uint64_t access_control;
} arch_mmu_debug_state_t;

void arch_mmu_debug_snapshot(arch_mmu_debug_state_t *state);

#endif /* _KERNEL_ARCH_MMU_DEBUG_H */

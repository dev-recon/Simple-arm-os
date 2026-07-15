/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/memory_layout.h
 * Layer: ARM64 / MMU memory layout
 *
 * Responsibilities:
 * - Describe the ARM64 identity direct mapping used by common kernel code.
 * - Keep virtual-to-physical layout constants beside the MMU backend.
 *
 * Notes:
 * - QEMU virt RAM starts at physical 0x40000000. The production common-kernel
 *   path keeps RAM identity mapped, matching its low-linked image.
 */

#ifndef ASM_ARM64_MEMORY_LAYOUT_H
#define ASM_ARM64_MEMORY_LAYOUT_H

#include <asm/mmu.h>
#include <asm/platform.h>

#define KERNEL_BOOT_IDENTITY_END \
    (ARMOS_PLATFORM_RAM_START + 0x00200000ULL)
#define KERNEL_DIRECT_MAP_BASE ARMOS_PLATFORM_RAM_START
#define KERNEL_DIRECT_MAP_SIZE ARMOS_PLATFORM_RAM_FALLBACK_SIZE
#define KERNEL_DIRECT_MAP_END \
    (KERNEL_DIRECT_MAP_BASE + KERNEL_DIRECT_MAP_SIZE)
#define KERNEL_DIRECT_MAP_OFFSET 0ULL

#endif /* ASM_ARM64_MEMORY_LAYOUT_H */

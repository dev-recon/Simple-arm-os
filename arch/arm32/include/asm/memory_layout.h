/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/memory_layout.h
 * Layer: ARM32 / memory layout
 *
 * Responsibilities:
 * - Define ARM32 kernel virtual layout constants.
 * - Keep architecture-specific direct-map and boot identity policy out of
 *   portable kernel headers.
 */

#ifndef ASM_ARM32_MEMORY_LAYOUT_H
#define ASM_ARM32_MEMORY_LAYOUT_H

#include <asm/platform.h>

/*
 * Kernel RAM mapping policy.
 *
 * ArmOS is moving away from relying on VA == PA for all RAM.  The kernel
 * image and early boot metadata still keep a small identity window so the
 * current ARM32 boot/linker path remains simple, but general allocator pages
 * must be accessed through the direct map.
 *
 * Direct map layout with the current 1GB TTBR0 / 3GB TTBR1 split:
 *   VA 0x60000000..0xDFFFFFFF -> platform RAM start + 2GB window
 *
 * That covers the supported ARM32 RAM profile and leaves 0xE0000000..
 * 0xEFFFFFFF for temporary mappings before the MMIO aliases at 0xF0000000.
 */
#define KERNEL_BOOT_IDENTITY_END 0x54100000u
#define KERNEL_DIRECT_MAP_BASE   0x60000000u
#define KERNEL_DIRECT_MAP_END    0xE0000000u
#define KERNEL_DIRECT_MAP_SIZE   (KERNEL_DIRECT_MAP_END - KERNEL_DIRECT_MAP_BASE)
#define KERNEL_DIRECT_MAP_OFFSET (KERNEL_DIRECT_MAP_BASE - ARMOS_PLATFORM_RAM_START)

#endif /* ASM_ARM32_MEMORY_LAYOUT_H */

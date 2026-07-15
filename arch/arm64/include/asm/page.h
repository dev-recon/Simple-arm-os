/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/page.h
 * Layer: ARM64 / memory management interface
 *
 * Responsibilities:
 * - Define the ARM64 page size, shift and alignment masks.
 * - Enforce the 4KB translation granule used by the current MMU port.
 *
 * Notes:
 * - Generic memory code consumes these constants through architecture-neutral
 *   page definitions.
 */

#ifndef ASM_ARM64_PAGE_H
#define ASM_ARM64_PAGE_H

#define ARCH_PAGE_SIZE        4096ULL
#define ARCH_PAGE_SHIFT       12u
#define ARCH_PAGE_OFFSET_MASK 0x0000000000000FFFULL
#define ARCH_PAGE_MASK        0xFFFFFFFFFFFFF000ULL

#if ARCH_PAGE_SIZE != 4096ULL
#error "ARM64 currently requires 4KB pages"
#endif

#endif /* ASM_ARM64_PAGE_H */

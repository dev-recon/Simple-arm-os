/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/cache.h
 * Layer: ARM64 / cache interface
 *
 * Responsibilities:
 * - Publish cache-line sizes required by aligned kernel data structures.
 * - Provide the architecture cache-line contract to generic code.
 *
 * Notes:
 * - The current QEMU virt and Cortex-A53/A72 targets use 64-byte cache lines.
 */

#ifndef ASM_ARM64_CACHE_H
#define ASM_ARM64_CACHE_H

#define ARCH_L1_CACHE_LINE_SIZE 64u
#define ARCH_L2_CACHE_LINE_SIZE 64u
#define ARCH_CACHE_LINE_SIZE    ARCH_L2_CACHE_LINE_SIZE

#endif /* ASM_ARM64_CACHE_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/cache.h
 * Layer: ARM32 / cache geometry
 *
 * Responsibilities:
 * - Expose cache-line sizes needed by generic alignment macros.
 * - Keep Cortex-A15 cache assumptions out of portable kernel headers.
 */

#ifndef ASM_ARM32_CACHE_H
#define ASM_ARM32_CACHE_H

#define ARCH_L1_CACHE_LINE_SIZE 32u
#define ARCH_L2_CACHE_LINE_SIZE 64u
#define ARCH_CACHE_LINE_SIZE    ARCH_L2_CACHE_LINE_SIZE

#endif /* ASM_ARM32_CACHE_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/cpu_features.h
 * Layer: ARM32 / CPU feature constants
 *
 * Responsibilities:
 * - Publish compile-time CPU feature assumptions for the current ARM32 port.
 * - Keep generic headers from including the large ARM register helper header.
 */

#ifndef ASM_ARM32_CPU_FEATURES_H
#define ASM_ARM32_CPU_FEATURES_H

#define ARCH_CORTEX_A15_FEATURES     1
#define ARCH_HAS_NEON                1
#define ARCH_HAS_VFP                 1
#define ARCH_HAS_GENERIC_TIMER       1
#define ARCH_HAS_LARGE_PHYS_ADDR     1
#define ARCH_HAS_VIRTUALIZATION      1

#endif /* ASM_ARM32_CPU_FEATURES_H */

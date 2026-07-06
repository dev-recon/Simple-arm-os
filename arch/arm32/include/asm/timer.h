/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/timer.h
 * Layer: ARM32 / timer constants
 *
 * Responsibilities:
 * - Define the ARM32 scheduler tick frequency.
 * - Provide the QEMU virt generic-timer fallback frequency used before DTB
 *   discovery has proven a hardware value.
 */

#ifndef ASM_ARM32_TIMER_H
#define ASM_ARM32_TIMER_H

#define ARCH_TIMER_TICK_HZ       1000u
#define ARCH_TIMER_FALLBACK_HZ   62500000u

#endif /* ASM_ARM32_TIMER_H */

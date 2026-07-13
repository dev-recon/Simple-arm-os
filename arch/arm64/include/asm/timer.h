/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/timer.h
 * Layer: ARM64 / CPU timer contract
 *
 * Responsibilities:
 * - Define the common scheduler tick rate for the ARM generic timer.
 * - Expose the selected platform frequency used before DTB discovery.
 *
 * Notes:
 * - Timer policy remains in the common kernel; this header describes only the
 *   architectural counter source consumed by that policy.
 */

#ifndef ASM_ARM64_TIMER_H
#define ASM_ARM64_TIMER_H

#include <asm/platform.h>

#define ARCH_TIMER_TICK_HZ     1000u
#define ARCH_TIMER_FALLBACK_HZ ARMOS_PLATFORM_TIMER_FALLBACK_HZ

#endif /* ASM_ARM64_TIMER_H */

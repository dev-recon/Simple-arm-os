/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_platform.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose the active platform MMIO and IRQ map to drivers.
 * - Keep generic driver headers from including asm/platform.h directly.
 *
 * Notes:
 * - This is intentionally a thin boundary during the multi-arch migration.
 *   Once a second platform exists, stable names can move here and the
 *   arch-specific header can keep only its local implementation details.
 */

#ifndef _KERNEL_ARCH_PLATFORM_H
#define _KERNEL_ARCH_PLATFORM_H

#include <asm/platform.h>

#endif /* _KERNEL_ARCH_PLATFORM_H */

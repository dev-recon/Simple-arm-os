/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_mmu.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose architecture MMU constants and opaque page-table helper types.
 * - Keep generic VM policy independent from concrete translation formats.
 *
 * Notes:
 * - Generic code includes this boundary instead of architecture headers.
 */

#ifndef _KERNEL_ARCH_MMU_H
#define _KERNEL_ARCH_MMU_H

#include <asm/mmu.h>

#endif /* _KERNEL_ARCH_MMU_H */

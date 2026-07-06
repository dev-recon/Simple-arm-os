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
 * - Expose architecture MMU constants and low-level MMU helper types while
 *   generic memory code is being separated from ARM32 short descriptors.
 *
 * Notes:
 * - This remains a compatibility bridge. The long-term shape is for generic
 *   memory.h to use opaque page-table and address-space operations only.
 */

#ifndef _KERNEL_ARCH_MMU_H
#define _KERNEL_ARCH_MMU_H

#include <asm/mmu.h>

#endif /* _KERNEL_ARCH_MMU_H */

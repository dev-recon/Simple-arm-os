/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_spinlock.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose architecture atomic and wait/wake primitives to generic spinlocks.
 * - Keep generic synchronization code from including architecture headers
 *   directly.
 *
 * Notes:
 * - ARM32 currently provides the implementation through LDREX/STREX, WFE/SEV,
 *   and CPSR interrupt-mask helpers.
 */

#ifndef _KERNEL_ARCH_SPINLOCK_H
#define _KERNEL_ARCH_SPINLOCK_H

#include <asm/spinlock.h>

#endif /* _KERNEL_ARCH_SPINLOCK_H */

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
 * - Implementations must provide atomic acquire/release, wait/wake, and local
 *   interrupt-mask operations with the same generic contract.
 */

#ifndef _KERNEL_ARCH_SPINLOCK_H
#define _KERNEL_ARCH_SPINLOCK_H

#include <asm/spinlock.h>

#endif /* _KERNEL_ARCH_SPINLOCK_H */

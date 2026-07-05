/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_power.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Declare the final platform power-off hook implemented by the active arch.
 * - Keep generic shutdown sequencing independent from PSCI/HVC details.
 *
 * Notes:
 * - This is intentionally tiny: shutdown policy stays in kernel/drivers/power.c.
 */

#ifndef _KERNEL_ARCH_POWER_H
#define _KERNEL_ARCH_POWER_H

void arch_system_off(void) __attribute__((noreturn));

#endif /* _KERNEL_ARCH_POWER_H */

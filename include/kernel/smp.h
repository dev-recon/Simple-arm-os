/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/smp.h
 * Layer: Kernel / SMP coordination
 *
 * Responsibilities:
 * - Expose CPU identity helpers to common kernel code.
 * - Keep SMP state explicit while ArmOS still boots a single CPU.
 *
 * Notes:
 * - This is deliberately passive for the first SMP step: no secondary CPU is
 *   started here.  The goal is to make existing code CPU-aware before bring-up.
 */

#ifndef _KERNEL_SMP_H
#define _KERNEL_SMP_H

#include <kernel/types.h>

#define ARMOS_MAX_CPUS 4U
#define ARMOS_BOOT_CPU 0U

void smp_init_boot_cpu(void);
uint32_t smp_processor_id(void);
uint32_t smp_boot_cpu_id(void);
uint32_t smp_online_cpu_count(void);
bool smp_is_boot_cpu(void);

#endif /* _KERNEL_SMP_H */

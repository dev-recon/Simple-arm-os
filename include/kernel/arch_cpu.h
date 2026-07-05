/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_cpu.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose CPU identity data used by procfs and diagnostics.
 * - Keep architecture register reads out of generic filesystem code.
 *
 * Notes:
 * - This is descriptive data only; CPU bring-up and scheduling stay elsewhere.
 */

#ifndef _KERNEL_ARCH_CPU_H
#define _KERNEL_ARCH_CPU_H

#include <kernel/types.h>

typedef struct arch_cpuinfo {
    const char* model_name;
    const char* features;
    const char* hardware;
    uint32_t implementer;
    uint32_t architecture;
    uint32_t part;
    uint32_t revision;
    uint32_t mpidr;
} arch_cpuinfo_t;

void arch_get_cpuinfo(arch_cpuinfo_t* info);

#endif /* _KERNEL_ARCH_CPU_H */

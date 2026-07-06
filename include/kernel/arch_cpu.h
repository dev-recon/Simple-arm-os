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
 * - Expose boot CPU control hooks used by generic bootstrap code.
 * - Keep architecture register reads and CPU-control instructions out of
 *   generic kernel code.
 *
 * Notes:
 * - CPU bring-up and scheduling stay in their dedicated SMP/task modules.
 *   These hooks cover only local CPU operations needed by generic boot and
 *   fatal-stop paths.
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
void arch_disable_interrupts(void);
void arch_enable_interrupts(void);
void arch_wait_for_interrupt(void);
void arch_disable_branch_predictor(void);
uint32_t arch_timer_frequency(void);
uint64_t arch_timer_counter(void);

#endif /* _KERNEL_ARCH_CPU_H */

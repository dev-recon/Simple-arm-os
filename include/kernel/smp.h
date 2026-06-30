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

typedef enum {
    SMP_CPU_OFFLINE = 0,
    SMP_CPU_BOOTING = 1,
    SMP_CPU_PARKED = 2,
    SMP_CPU_ONLINE = 3,
} smp_cpu_state_t;

typedef struct smp_cpu_info {
    uint32_t cpu_id;
    volatile uint32_t state;
    volatile uint32_t irq_count;
    volatile uint32_t ipi_count;
    volatile uint32_t park_heartbeat;
    int32_t start_result;
} smp_cpu_info_t;

void smp_init_boot_cpu(void);
void smp_start_secondary_cpus(void);
void smp_secondary_main(uint32_t cpu_id) __attribute__((noreturn));
uint32_t smp_processor_id(void);
uint32_t smp_boot_cpu_id(void);
uint32_t smp_seen_cpu_mask(void);
uint32_t smp_online_cpu_count(void);
uint32_t smp_possible_cpu_count(void);
int32_t smp_cpu_start_result(uint32_t cpu_id);
smp_cpu_state_t smp_cpu_state(uint32_t cpu_id);
const char* smp_cpu_state_name(uint32_t cpu_id);
const smp_cpu_info_t* smp_cpu_info(uint32_t cpu_id);
void smp_note_irq(uint32_t cpu_id);
void smp_note_ipi(uint32_t cpu_id);
bool smp_is_boot_cpu(void);
bool smp_cpu_seen(uint32_t cpu_id);
bool smp_cpu_online(uint32_t cpu_id);
bool smp_scheduler_can_run_on_current_cpu(void);
uint32_t smp_scheduler_reject_count(void);

#endif /* _KERNEL_SMP_H */

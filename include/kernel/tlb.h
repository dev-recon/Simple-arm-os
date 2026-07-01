/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/tlb.h
 * Layer: Kernel / MMU and SMP coordination
 *
 * Responsibilities:
 * - Provide one named interface for TLB invalidation.
 * - Hide whether an invalidation is local-only or SMP-wide.
 *
 * Notes:
 * - Parked secondary CPUs acknowledge shootdown IPIs before they are allowed
 *   to join the scheduler. This validates the SMP maintenance path while the
 *   rest of the kernel remains single-scheduler-CPU.
 */

#ifndef _KERNEL_TLB_H
#define _KERNEL_TLB_H

#include <kernel/types.h>

void tlb_shootdown_all(void);
void tlb_shootdown_page(uint32_t vaddr);
void tlb_shootdown_page_asid(uint32_t vaddr, uint32_t asid);
void tlb_shootdown_asid(uint32_t asid);
void tlb_handle_remote_ipi(uint32_t cpu_id);

uint32_t tlb_shootdown_total_count(void);
uint32_t tlb_shootdown_remote_count(void);
uint32_t tlb_shootdown_deferred_count(void);
uint32_t tlb_shootdown_generation(void);
uint32_t tlb_shootdown_cpu_ack(uint32_t cpu_id);

#endif /* _KERNEL_TLB_H */

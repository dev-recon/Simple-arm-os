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
 * - Secondary CPUs are currently parked, so shootdown operations resolve to
 *   local maintenance on CPU0. When more CPUs become online, this is the place
 *   to add IPI rendezvous and remote acknowledgement.
 */

#ifndef _KERNEL_TLB_H
#define _KERNEL_TLB_H

#include <kernel/types.h>

void tlb_shootdown_all(void);
void tlb_shootdown_page(uint32_t vaddr);
void tlb_shootdown_page_asid(uint32_t vaddr, uint32_t asid);
void tlb_shootdown_asid(uint32_t asid);

uint32_t tlb_shootdown_total_count(void);
uint32_t tlb_shootdown_remote_count(void);
uint32_t tlb_shootdown_deferred_count(void);

#endif /* _KERNEL_TLB_H */

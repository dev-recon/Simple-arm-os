/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/user_vm.h
 * Layer: ARM64 / user address spaces
 *
 * Responsibilities:
 * - Own bootstrap user translation tables, mappings and ASID identity.
 * - Track mapping generations for safe resident-ASID activation.
 *
 * Notes:
 * - Allocation and residency metadata remain single-CPU bootstrap services.
 */

#ifndef ASM_ARM64_USER_VM_H
#define ASM_ARM64_USER_VM_H

#include <asm/mmu.h>
#include <kernel/early_page_allocator.h>
#include <kernel/types.h>

#define ARM64_USER_VM_MAX_MAPPINGS 8u

typedef struct {
    vaddr_t virtual_address;
    paddr_t physical_address;
    unsigned int flags;
} arm64_user_vm_mapping_t;

typedef struct {
    paddr_t l1;
    paddr_t l2;
    paddr_t l3;
    vaddr_t l3_window;
    unsigned int asid;
    unsigned int mapping_count;
    uint32_t tlb_generation;
    arm64_user_vm_mapping_t mappings[ARM64_USER_VM_MAX_MAPPINGS];
} arm64_user_vm_t;

int arm64_user_vm_init(arm64_user_vm_t *vm,
                       early_page_allocator_t *allocator);
int arm64_user_vm_map_new_page(arm64_user_vm_t *vm,
                               early_page_allocator_t *allocator,
                               vaddr_t virtual_address,
                               unsigned int flags,
                               paddr_t *physical_address);
int arm64_user_vm_activate(const arm64_user_vm_t *vm);
int arm64_user_vm_lookup(const arm64_user_vm_t *vm,
                         vaddr_t virtual_address,
                         paddr_t *physical_address,
                         unsigned int *flags);
int arm64_user_vm_validate_range(const arm64_user_vm_t *vm,
                                 vaddr_t address,
                                 size_t length,
                                 unsigned int required_flags);
int arm64_user_vm_destroy(arm64_user_vm_t *vm,
                          early_page_allocator_t *allocator);
uint64_t arm64_user_vm_tlb_flush_count(void);
uint64_t arm64_user_vm_tlb_preserve_count(void);

#endif

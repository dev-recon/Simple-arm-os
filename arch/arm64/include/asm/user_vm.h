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
 * - Grow bounded L2/L3 inventories and unmap owned pages at runtime.
 * - Map and unmap anonymous page ranges with transactional allocation.
 * - Clone complete user spaces with independent eagerly copied pages.
 * - Expose that identity through the generic vm_space_t contract.
 * - Publish mapped user pages through the generic sorted VMA list.
 * - Track mapping generations for safe resident-ASID activation.
 *
 * Notes:
 * - Allocation and residency metadata remain single-CPU services.
 * - High-half entry must rebind the opaque backend pointer before low-map
 *   retirement because the object is created through its identity alias.
 */

#ifndef ASM_ARM64_USER_VM_H
#define ASM_ARM64_USER_VM_H

#include <asm/mmu.h>
#include <kernel/early_page_allocator.h>
#include <kernel/memory.h>
#include <kernel/types.h>

#define ARM64_USER_VM_MAX_MAPPINGS 128u
#define ARM64_USER_VM_MAX_L2_TABLES 16u
#define ARM64_USER_VM_MAX_L3_TABLES 16u
#define ARM64_USER_VM_MAGIC 0x41564D36u

typedef struct {
    vma_t vma;
    paddr_t physical_address;
} arm64_user_vm_mapping_t;

typedef struct {
    uint32_t l1_index;
    paddr_t table;
} arm64_user_vm_l2_table_t;

typedef struct {
    uint32_t l1_index;
    uint32_t l2_index;
    paddr_t table;
} arm64_user_vm_l3_table_t;

typedef struct {
    vm_space_t space;
    uint32_t magic;
    paddr_t l1;
    unsigned int asid;
    unsigned int mapping_count;
    unsigned int l2_table_count;
    unsigned int l3_table_count;
    uint32_t tlb_generation;
    arm64_user_vm_l2_table_t l2_tables[ARM64_USER_VM_MAX_L2_TABLES];
    arm64_user_vm_l3_table_t l3_tables[ARM64_USER_VM_MAX_L3_TABLES];
    arm64_user_vm_mapping_t mappings[ARM64_USER_VM_MAX_MAPPINGS];
} arm64_user_vm_t;

const vm_space_t *arm64_user_vm_space(const arm64_user_vm_t *vm);
const arm64_user_vm_t *arm64_user_vm_from_space(const vm_space_t *space);
int arm64_user_vm_validate_identity(const arm64_user_vm_t *vm);
int arm64_user_vm_rebind_space(arm64_user_vm_t *vm);
int arm64_user_vm_activate_space(const vm_space_t *space);
int arm64_user_vm_validate_space_range(const vm_space_t *space,
                                       vaddr_t address,
                                       size_t length,
                                       unsigned int required_flags);

int arm64_user_vm_init(arm64_user_vm_t *vm,
                       early_page_allocator_t *allocator);
int arm64_user_vm_clone_eager(arm64_user_vm_t *destination,
                              const arm64_user_vm_t *source,
                              early_page_allocator_t *allocator);
int arm64_user_vm_map_new_page(arm64_user_vm_t *vm,
                               early_page_allocator_t *allocator,
                               vaddr_t virtual_address,
                               unsigned int flags,
                               paddr_t *physical_address);
int arm64_user_vm_unmap_page(arm64_user_vm_t *vm,
                             early_page_allocator_t *allocator,
                             vaddr_t virtual_address);
int arm64_user_vm_map_anonymous(arm64_user_vm_t *vm,
                                early_page_allocator_t *allocator,
                                vaddr_t virtual_address,
                                size_t length,
                                unsigned int flags);
int arm64_user_vm_unmap_range(arm64_user_vm_t *vm,
                              early_page_allocator_t *allocator,
                              vaddr_t virtual_address,
                              size_t length);
int arm64_user_vm_reserve_anonymous(arm64_user_vm_t *vm,
                                    vaddr_t virtual_address,
                                    size_t length,
                                    unsigned int flags);
int arm64_user_vm_handle_page_fault(arm64_user_vm_t *vm,
                                    early_page_allocator_t *allocator,
                                    vaddr_t fault_address,
                                    int is_write,
                                    int is_execute,
                                    paddr_t *physical_address);
int arm64_user_vm_set_brk(arm64_user_vm_t *vm,
                          early_page_allocator_t *allocator,
                          vaddr_t requested,
                          vaddr_t *result);
int arm64_user_vm_mmap_anonymous(arm64_user_vm_t *vm,
                                 vaddr_t hint,
                                 size_t length,
                                 unsigned int flags,
                                 vaddr_t *result);
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

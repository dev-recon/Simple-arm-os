/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/mmu/user_vm.c
 * Layer: ARM64 / user address spaces
 *
 * Responsibilities:
 * - Own bootstrap user tables, mapped pages and ASID allocation.
 * - Bind the ARM64 backend to the generic vm_space_t identity.
 * - Maintain a sorted generic VMA list for every bootstrap mapping.
 * - Track mapping generations and resident ASID translations.
 * - Avoid redundant TLBI operations for unchanged address spaces.
 *
 * Notes:
 * - State is intentionally single-CPU until the ARM64 scheduler is online.
 */

#include <asm/mmu.h>
#include <asm/user_vm.h>

#define ARM64_ASID_COUNT       256u
#define ARM64_ASID_BITMAP_SIZE (ARM64_ASID_COUNT / 8u)
#define ARM64_L3_WINDOW_SIZE   0x200000ULL
#define ARM64_TTBR_TABLE_MASK  0x0000FFFFFFFFF000ULL

static uint8_t arm64_asid_bitmap[ARM64_ASID_BITMAP_SIZE];
static uint32_t next_tlb_generation = 1;
static uint64_t tlb_flush_count;
static uint64_t tlb_preserve_count;

typedef struct {
    paddr_t table;
    uint32_t generation;
} arm64_asid_residency_t;

static arm64_asid_residency_t arm64_asid_residency[ARM64_ASID_COUNT];

_Static_assert(ARM64_USER_PAGE_READ == VMA_READ,
               "ARM64 read permission must match generic VMA_READ");
_Static_assert(ARM64_USER_PAGE_WRITE == VMA_WRITE,
               "ARM64 write permission must match generic VMA_WRITE");
_Static_assert(ARM64_USER_PAGE_EXEC == VMA_EXEC,
               "ARM64 execute permission must match generic VMA_EXEC");

static uint32_t allocate_tlb_generation(void)
{
    uint32_t generation = next_tlb_generation++;

    if (generation == 0) {
        generation = next_tlb_generation++;
        if (generation == 0)
            generation = 1;
    }
    return generation;
}

static void clear_bytes(void *address, size_t length)
{
    uint8_t *bytes = address;
    size_t index;

    for (index = 0; index < length; index++)
        bytes[index] = 0;
}

static int asid_is_allocated(unsigned int asid)
{
    return (arm64_asid_bitmap[asid >> 3] & (1u << (asid & 7u))) != 0;
}

static unsigned int allocate_asid(void)
{
    unsigned int asid;

    for (asid = 1; asid < ARM64_ASID_COUNT; asid++) {
        if (!asid_is_allocated(asid)) {
            arm64_asid_bitmap[asid >> 3] |= (uint8_t)(1u << (asid & 7u));
            return asid;
        }
    }
    return 0;
}

static void release_asid(unsigned int asid)
{
    if (asid > 0 && asid < ARM64_ASID_COUNT)
        arm64_asid_bitmap[asid >> 3] &=
            (uint8_t)~(1u << (asid & 7u));
}

static void arm64_user_vm_rebuild_vma_list(arm64_user_vm_t *vm)
{
    unsigned int index;

    vm->space.vma_list = NULL;
    for (index = 0; index < vm->mapping_count; index++) {
        vma_t *vma = &vm->mappings[index].vma;
        vma_t **link = &vm->space.vma_list;

        vma->next = NULL;
        while (*link && (*link)->start < vma->start)
            link = &(*link)->next;
        vma->next = *link;
        *link = vma;
    }
}

static const arm64_user_vm_mapping_t *arm64_user_vm_mapping_for_vma(
    const arm64_user_vm_t *vm,
    const vma_t *vma)
{
    unsigned int index;

    for (index = 0; index < vm->mapping_count; index++) {
        if (&vm->mappings[index].vma == vma)
            return &vm->mappings[index];
    }
    return NULL;
}

static int arm64_user_vm_validate_vmas(const arm64_user_vm_t *vm)
{
    const arm64_user_vm_mapping_t *mapping;
    const vma_t *vma = vm->space.vma_list;
    vaddr_t previous_end = 0;
    unsigned int count = 0;

    if (vm->mapping_count > ARM64_USER_VM_MAX_MAPPINGS)
        return -1;
    while (vma) {
        mapping = arm64_user_vm_mapping_for_vma(vm, vma);
        if (count >= vm->mapping_count ||
            !mapping || mapping->physical_address == 0 ||
            (mapping->physical_address & PAGE_OFFSET_MASK) != 0 ||
            (vma->start & PAGE_OFFSET_MASK) != 0 ||
            vma->end != vma->start + PAGE_SIZE ||
            vma->end <= vma->start || vma->start < previous_end ||
            (vma->flags & ~(VMA_READ | VMA_WRITE | VMA_EXEC)) != 0 ||
            (vma->flags & VMA_READ) == 0 ||
            (vma->flags & (VMA_WRITE | VMA_EXEC)) ==
                (VMA_WRITE | VMA_EXEC))
            return -1;
        previous_end = vma->end;
        count++;
        vma = vma->next;
    }
    if (count != vm->mapping_count)
        return -1;
    return 0;
}

static int arm64_user_vm_validate_fields(const arm64_user_vm_t *vm)
{
    if (!vm || vm->magic != ARM64_USER_VM_MAGIC || vm->l1 == 0 ||
        vm->asid == 0 || vm->space.pgdir == NULL ||
        vm->space.pgdir_alloc == NULL || vm->space.asid != vm->asid ||
        (paddr_t)(uintptr_t)vm->space.pgdir != vm->l1 ||
        (paddr_t)(uintptr_t)vm->space.pgdir_alloc != vm->l1 ||
        vm->space.heap_start != USER_HEAP_START ||
        vm->space.heap_end != USER_HEAP_END ||
        vm->space.brk < vm->space.heap_start ||
        vm->space.brk > vm->space.heap_end ||
        vm->space.stack_start != USER_STACK_TOP ||
        arm64_user_vm_validate_vmas(vm) != 0)
        return -1;
    return 0;
}

int arm64_user_vm_validate_identity(const arm64_user_vm_t *vm)
{
    if (arm64_user_vm_validate_fields(vm) != 0 ||
        vm->space.arch_private != vm)
        return -1;
    return 0;
}

int arm64_user_vm_rebind_space(arm64_user_vm_t *vm)
{
    if (!vm || vm->magic != ARM64_USER_VM_MAGIC || vm->l1 == 0 ||
        vm->asid == 0 || vm->mapping_count > ARM64_USER_VM_MAX_MAPPINGS)
        return -1;
    arm64_user_vm_rebuild_vma_list(vm);
    vm->space.arch_private = vm;
    return arm64_user_vm_validate_identity(vm);
}

const vm_space_t *arm64_user_vm_space(const arm64_user_vm_t *vm)
{
    if (arm64_user_vm_validate_identity(vm) != 0)
        return NULL;
    return &vm->space;
}

const arm64_user_vm_t *arm64_user_vm_from_space(const vm_space_t *space)
{
    const arm64_user_vm_t *vm;

    if (!space || !space->arch_private)
        return NULL;
    vm = (const arm64_user_vm_t *)space->arch_private;
    if (&vm->space != space ||
        arm64_user_vm_validate_identity(vm) != 0)
        return NULL;
    return vm;
}

int arm64_user_vm_init(arm64_user_vm_t *vm,
                       early_page_allocator_t *allocator)
{
    paddr_t table_pages;
    unsigned int asid;

    if (!vm || !allocator)
        return -1;

    clear_bytes(vm, sizeof(*vm));
    asid = allocate_asid();
    if (asid == 0)
        return -2;
    if (early_page_alloc_pages(allocator, 3, &table_pages) != 0) {
        release_asid(asid);
        return -3;
    }
    if (arm64_mmu_prepare_empty_ttbr0(table_pages) != 0) {
        early_page_free_pages(allocator, table_pages, 3);
        release_asid(asid);
        return -4;
    }

    vm->l1 = table_pages;
    vm->l2 = table_pages + PAGE_SIZE;
    vm->l3 = table_pages + 2 * PAGE_SIZE;
    vm->asid = asid;
    vm->tlb_generation = allocate_tlb_generation();
    vm->space.pgdir = (pgdir_t)(uintptr_t)vm->l1;
    vm->space.pgdir_alloc = (pgdir_t)(uintptr_t)vm->l1;
    vm->space.vma_list = NULL;
    vm->space.arch_private = vm;
    vm->space.heap_start = USER_HEAP_START;
    vm->space.heap_end = USER_HEAP_END;
    vm->space.brk = USER_HEAP_START;
    vm->space.stack_start = USER_STACK_TOP;
    vm->space.asid = asid;
    vm->magic = ARM64_USER_VM_MAGIC;
    return 0;
}

int arm64_user_vm_map_new_page(arm64_user_vm_t *vm,
                               early_page_allocator_t *allocator,
                               vaddr_t virtual_address,
                               unsigned int flags,
                               paddr_t *physical_address)
{
    paddr_t page;
    vaddr_t window;
    unsigned int index;
    int result;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator ||
        !physical_address ||
        (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        vm->mapping_count >= ARM64_USER_VM_MAX_MAPPINGS)
        return -1;

    window = virtual_address & ~(ARM64_L3_WINDOW_SIZE - 1u);
    if (vm->mapping_count != 0 && window != vm->l3_window)
        return -2;
    for (index = 0; index < vm->mapping_count; index++) {
        if (vm->mappings[index].vma.start == virtual_address)
            return -3;
    }

    if (early_page_alloc_pages(allocator, 1, &page) != 0)
        return -4;

    if (vm->mapping_count == 0) {
        result = arm64_mmu_prepare_user_page(vm->l1, vm->l2, vm->l3,
                                             virtual_address, page, flags);
    } else {
        result = arm64_mmu_prepare_user_l3_page(vm->l3, virtual_address,
                                                page, flags);
    }
    if (result != 0) {
        early_page_free_pages(allocator, page, 1);
        return -5;
    }

    index = vm->mapping_count++;
    vm->mappings[index].vma.start = virtual_address;
    vm->mappings[index].vma.end = virtual_address + PAGE_SIZE;
    vm->mappings[index].vma.flags = flags;
    vm->mappings[index].vma.shm_id = 0;
    vm->mappings[index].vma.next = NULL;
    vm->mappings[index].physical_address = page;
    arm64_user_vm_rebuild_vma_list(vm);
    vm->l3_window = window;
    vm->tlb_generation = allocate_tlb_generation();
    *physical_address = page;
    return 0;
}

int arm64_user_vm_activate(const arm64_user_vm_t *vm)
{
    arm64_asid_residency_t *residency;
    int result;

    if (arm64_user_vm_validate_identity(vm) != 0)
        return -1;

    residency = &arm64_asid_residency[vm->asid];
    if (residency->table == vm->l1 &&
        residency->generation == vm->tlb_generation) {
        result = arm64_mmu_switch_user_ttbr0_preserve(vm->l1, vm->asid);
        if (result == 0)
            tlb_preserve_count++;
        return result;
    }

    result = arm64_mmu_switch_user_ttbr0(vm->l1, vm->asid);
    if (result == 0) {
        residency->table = vm->l1;
        residency->generation = vm->tlb_generation;
        tlb_flush_count++;
    }
    return result;
}

int arm64_user_vm_activate_space(const vm_space_t *space)
{
    const arm64_user_vm_t *vm = arm64_user_vm_from_space(space);

    if (!vm)
        return -1;
    return arm64_user_vm_activate(vm);
}

uint64_t arm64_user_vm_tlb_flush_count(void)
{
    return tlb_flush_count;
}

uint64_t arm64_user_vm_tlb_preserve_count(void)
{
    return tlb_preserve_count;
}

int arm64_user_vm_lookup(const arm64_user_vm_t *vm,
                         vaddr_t virtual_address,
                         paddr_t *physical_address,
                         unsigned int *flags)
{
    const arm64_user_vm_mapping_t *mapping;
    const vma_t *vma;

    if (arm64_user_vm_validate_identity(vm) != 0)
        return -1;
    for (vma = vm->space.vma_list; vma; vma = vma->next) {
        if (vma->start != virtual_address)
            continue;
        mapping = arm64_user_vm_mapping_for_vma(vm, vma);
        if (!mapping)
            return -1;
        if (physical_address)
            *physical_address = mapping->physical_address;
        if (flags)
            *flags = vma->flags;
        return 0;
    }
    return -2;
}

int arm64_user_vm_validate_range(const arm64_user_vm_t *vm,
                                 vaddr_t address,
                                 size_t length,
                                 unsigned int required_flags)
{
    vaddr_t cursor;
    vaddr_t end;
    vaddr_t page;
    vaddr_t next;
    unsigned int flags;

    if (arm64_user_vm_validate_identity(vm) != 0 || required_flags == 0 ||
        (required_flags & ~(ARM64_USER_PAGE_READ |
                            ARM64_USER_PAGE_WRITE |
                            ARM64_USER_PAGE_EXEC)) != 0)
        return -1;
    if (length == 0)
        return 0;

    end = address + (vaddr_t)length;
    if (end <= address)
        return -2;

    cursor = address;
    while (cursor < end) {
        page = cursor & PAGE_MASK;
        if (arm64_user_vm_lookup(vm, page, NULL, &flags) != 0 ||
            (flags & required_flags) != required_flags)
            return -3;
        next = page + PAGE_SIZE;
        if (next <= page)
            return -2;
        cursor = next < end ? next : end;
    }
    return 0;
}

int arm64_user_vm_validate_space_range(const vm_space_t *space,
                                       vaddr_t address,
                                       size_t length,
                                       unsigned int required_flags)
{
    const arm64_user_vm_t *vm = arm64_user_vm_from_space(space);

    if (!vm)
        return -1;
    return arm64_user_vm_validate_range(vm, address, length,
                                        required_flags);
}

int arm64_user_vm_destroy(arm64_user_vm_t *vm,
                          early_page_allocator_t *allocator)
{
    unsigned int index;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator)
        return -1;
    if ((arm64_mmu_read_ttbr0() & ARM64_TTBR_TABLE_MASK) == vm->l1)
        return -2;

    for (index = 0; index < vm->mapping_count; index++) {
        if (early_page_free_pages(allocator,
                                  vm->mappings[index].physical_address,
                                  1) != 0)
            return -3;
    }
    if (early_page_free_pages(allocator, vm->l1, 3) != 0)
        return -4;

    release_asid(vm->asid);
    clear_bytes(vm, sizeof(*vm));
    return 0;
}

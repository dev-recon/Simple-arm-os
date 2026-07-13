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
 * - Grow bounded L2/L3 table inventories and retire mapped pages.
 * - Provide transactional anonymous range mapping and table reclamation.
 * - Clone user spaces transactionally with independent resident pages.
 * - Reserve lazy brk/mmap pages and resolve their EL0 translation faults.
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

static void arm64_user_vm_publish_targeted_generation(arm64_user_vm_t *vm)
{
    arm64_asid_residency_t *residency =
        &arm64_asid_residency[vm->asid];

    if (residency->table == vm->l1)
        residency->generation = vm->tlb_generation;
}

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

static void copy_bytes(void *destination, const void *source, size_t length)
{
    uint8_t *destination_bytes = destination;
    const uint8_t *source_bytes = source;
    size_t index;

    for (index = 0; index < length; index++)
        destination_bytes[index] = source_bytes[index];
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

static arm64_user_vm_l2_table_t *arm64_user_vm_find_l2(
    arm64_user_vm_t *vm,
    vaddr_t virtual_address)
{
    uint32_t l1_index = (uint32_t)((virtual_address >> 30) & 0x1ffu);
    unsigned int index;

    for (index = 0; index < vm->l2_table_count; index++) {
        if (vm->l2_tables[index].l1_index == l1_index)
            return &vm->l2_tables[index];
    }
    return NULL;
}

static arm64_user_vm_l3_table_t *arm64_user_vm_find_l3(
    arm64_user_vm_t *vm,
    vaddr_t virtual_address)
{
    uint32_t l1_index = (uint32_t)((virtual_address >> 30) & 0x1ffu);
    uint32_t l2_index = (uint32_t)((virtual_address >> 21) & 0x1ffu);
    unsigned int index;

    for (index = 0; index < vm->l3_table_count; index++) {
        if (vm->l3_tables[index].l1_index == l1_index &&
            vm->l3_tables[index].l2_index == l2_index)
            return &vm->l3_tables[index];
    }
    return NULL;
}

static unsigned int arm64_user_vm_mapping_index(
    const arm64_user_vm_t *vm,
    vaddr_t virtual_address)
{
    unsigned int index;

    for (index = 0; index < vm->mapping_count; index++) {
        if (vm->mappings[index].vma.start == virtual_address)
            return index;
    }
    return vm->mapping_count;
}

static int arm64_user_vm_l3_has_mapping(const arm64_user_vm_t *vm,
                                        uint32_t l1_index,
                                        uint32_t l2_index)
{
    unsigned int index;

    for (index = 0; index < vm->mapping_count; index++) {
        vaddr_t address = vm->mappings[index].vma.start;

        if (vm->mappings[index].physical_address != 0 &&
            ((address >> 30) & 0x1ffu) == l1_index &&
            ((address >> 21) & 0x1ffu) == l2_index)
            return 1;
    }
    return 0;
}

static int arm64_user_vm_l2_has_l3(const arm64_user_vm_t *vm,
                                   uint32_t l1_index)
{
    unsigned int index;

    for (index = 0; index < vm->l3_table_count; index++) {
        if (vm->l3_tables[index].l1_index == l1_index)
            return 1;
    }
    return 0;
}

static int arm64_user_vm_reclaim_empty_tables(
    arm64_user_vm_t *vm,
    early_page_allocator_t *allocator,
    vaddr_t virtual_address)
{
    arm64_user_vm_l2_table_t *l2;
    arm64_user_vm_l3_table_t *l3;
    paddr_t table;
    uint32_t l1_index = (uint32_t)((virtual_address >> 30) & 0x1ffu);
    uint32_t l2_index = (uint32_t)((virtual_address >> 21) & 0x1ffu);
    unsigned int index;
    unsigned int last;

    l3 = arm64_user_vm_find_l3(vm, virtual_address);
    if (l3 && !arm64_user_vm_l3_has_mapping(vm, l1_index, l2_index)) {
        l2 = arm64_user_vm_find_l2(vm, virtual_address);
        if (!l2 || arm64_mmu_remove_user_l3(
                l2->table, l3->table, virtual_address, vm->asid) != 0)
            return -1;
        table = l3->table;
        if (early_page_free_pages(allocator, table, 1) != 0)
            return -2;
        for (index = 0; index < vm->l3_table_count; index++) {
            if (vm->l3_tables[index].table == table)
                break;
        }
        if (index == vm->l3_table_count)
            return -3;
        last = vm->l3_table_count - 1;
        if (index != last)
            vm->l3_tables[index] = vm->l3_tables[last];
        clear_bytes(&vm->l3_tables[last], sizeof(vm->l3_tables[last]));
        vm->l3_table_count--;
    }

    l2 = arm64_user_vm_find_l2(vm, virtual_address);
    if (l2 && !arm64_user_vm_l2_has_l3(vm, l1_index)) {
        table = l2->table;
        if (arm64_mmu_remove_user_l2(vm->l1, table,
                                     virtual_address, vm->asid) != 0)
            return -4;
        if (early_page_free_pages(allocator, table, 1) != 0)
            return -5;
        for (index = 0; index < vm->l2_table_count; index++) {
            if (vm->l2_tables[index].table == table)
                break;
        }
        if (index == vm->l2_table_count)
            return -6;
        last = vm->l2_table_count - 1;
        if (index != last)
            vm->l2_tables[index] = vm->l2_tables[last];
        clear_bytes(&vm->l2_tables[last], sizeof(vm->l2_tables[last]));
        vm->l2_table_count--;
    }
    return 0;
}

static int arm64_user_vm_validate_tables(const arm64_user_vm_t *vm)
{
    unsigned int first;
    unsigned int second;
    int parent_found;

    if (vm->l2_table_count > ARM64_USER_VM_MAX_L2_TABLES ||
        vm->l3_table_count > ARM64_USER_VM_MAX_L3_TABLES)
        return -1;
    for (first = 0; first < vm->l2_table_count; first++) {
        if (vm->l2_tables[first].l1_index >= 512u ||
            vm->l2_tables[first].table == 0 ||
            (vm->l2_tables[first].table & PAGE_OFFSET_MASK) != 0 ||
            vm->l2_tables[first].table == vm->l1)
            return -1;
        for (second = first + 1; second < vm->l2_table_count; second++) {
            if (vm->l2_tables[first].l1_index ==
                    vm->l2_tables[second].l1_index ||
                vm->l2_tables[first].table ==
                    vm->l2_tables[second].table)
                return -1;
        }
    }
    for (first = 0; first < vm->l3_table_count; first++) {
        if (vm->l3_tables[first].l1_index >= 512u ||
            vm->l3_tables[first].l2_index >= 512u ||
            vm->l3_tables[first].table == 0 ||
            (vm->l3_tables[first].table & PAGE_OFFSET_MASK) != 0 ||
            vm->l3_tables[first].table == vm->l1)
            return -1;
        parent_found = 0;
        for (second = 0; second < vm->l2_table_count; second++) {
            if (vm->l2_tables[second].l1_index ==
                vm->l3_tables[first].l1_index)
                parent_found = 1;
        }
        if (!parent_found)
            return -1;
        for (second = first + 1; second < vm->l3_table_count; second++) {
            if (vm->l3_tables[first].l1_index ==
                    vm->l3_tables[second].l1_index &&
                vm->l3_tables[first].l2_index ==
                    vm->l3_tables[second].l2_index)
                return -1;
            if (vm->l3_tables[first].table ==
                vm->l3_tables[second].table)
                return -1;
        }
        for (second = 0; second < vm->l2_table_count; second++) {
            if (vm->l3_tables[first].table ==
                vm->l2_tables[second].table)
                return -1;
        }
    }
    return 0;
}

static int arm64_user_vm_flags_valid(unsigned int flags)
{
    if ((flags & VMA_READ) == 0 ||
        (flags & ~(VMA_READ | VMA_WRITE | VMA_EXEC | VMA_LAZY)) != 0)
        return 0;
    return (flags & (VMA_WRITE | VMA_EXEC)) !=
           (VMA_WRITE | VMA_EXEC);
}

static int arm64_user_vm_ensure_l3(arm64_user_vm_t *vm,
                                   early_page_allocator_t *allocator,
                                   vaddr_t virtual_address,
                                   paddr_t *l3_address)
{
    arm64_user_vm_l2_table_t *l2 =
        arm64_user_vm_find_l2(vm, virtual_address);
    arm64_user_vm_l3_table_t *l3 =
        arm64_user_vm_find_l3(vm, virtual_address);
    paddr_t table;

    if (l3) {
        *l3_address = l3->table;
        return 0;
    }
    if (!l2) {
        if (vm->l2_table_count >= ARM64_USER_VM_MAX_L2_TABLES ||
            early_page_alloc_pages(allocator, 1, &table) != 0)
            return -1;
        if (arm64_mmu_install_user_l2(vm->l1, table,
                                      virtual_address) != 0) {
            early_page_free_pages(allocator, table, 1);
            return -2;
        }
        l2 = &vm->l2_tables[vm->l2_table_count++];
        l2->l1_index = (uint32_t)((virtual_address >> 30) & 0x1ffu);
        l2->table = table;
    }
    if (vm->l3_table_count >= ARM64_USER_VM_MAX_L3_TABLES ||
        early_page_alloc_pages(allocator, 1, &table) != 0)
        return -3;
    if (arm64_mmu_install_user_l3(l2->table, table,
                                  virtual_address) != 0) {
        early_page_free_pages(allocator, table, 1);
        return -4;
    }
    l3 = &vm->l3_tables[vm->l3_table_count++];
    l3->l1_index = (uint32_t)((virtual_address >> 30) & 0x1ffu);
    l3->l2_index = (uint32_t)((virtual_address >> 21) & 0x1ffu);
    l3->table = table;
    *l3_address = table;
    return 0;
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
            !mapping ||
            (mapping->physical_address == 0 &&
             (vma->flags & VMA_LAZY) == 0) ||
            (mapping->physical_address != 0 &&
             (mapping->physical_address & PAGE_OFFSET_MASK) != 0) ||
            (vma->start & PAGE_OFFSET_MASK) != 0 ||
            vma->end != vma->start + PAGE_SIZE ||
            vma->end <= vma->start || vma->start < previous_end ||
            (vma->flags & ~(VMA_READ | VMA_WRITE | VMA_EXEC |
                            VMA_LAZY)) != 0 ||
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
        arm64_user_vm_validate_tables(vm) != 0 ||
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
        vm->asid == 0 || vm->mapping_count > ARM64_USER_VM_MAX_MAPPINGS ||
        arm64_user_vm_validate_tables(vm) != 0)
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
    if (early_page_alloc_pages(allocator, 1, &table_pages) != 0) {
        release_asid(asid);
        return -3;
    }
    if (arm64_mmu_prepare_empty_ttbr0(table_pages) != 0) {
        early_page_free_pages(allocator, table_pages, 1);
        release_asid(asid);
        return -4;
    }

    vm->l1 = table_pages;
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

int arm64_user_vm_clone_eager(arm64_user_vm_t *destination,
                              const arm64_user_vm_t *source,
                              early_page_allocator_t *allocator)
{
    const arm64_user_vm_mapping_t *source_mapping;
    arm64_user_vm_mapping_t *destination_mapping;
    paddr_t destination_page;
    unsigned int destination_index;
    unsigned int flags;
    unsigned int index;
    int result;

    if (!destination || !source || destination == source || !allocator ||
        arm64_user_vm_validate_identity(source) != 0)
        return -1;
    if (arm64_user_vm_init(destination, allocator) != 0)
        return -2;

    for (index = 0; index < source->mapping_count; index++) {
        source_mapping = &source->mappings[index];
        if (source_mapping->vma.shm_id != 0)
            goto failed;
        flags = source_mapping->vma.flags;
        if (source_mapping->physical_address == 0) {
            result = arm64_user_vm_reserve_anonymous(
                destination, source_mapping->vma.start, PAGE_SIZE, flags);
        } else {
            result = arm64_user_vm_map_new_page(
                destination, allocator, source_mapping->vma.start,
                flags & ~VMA_LAZY, &destination_page);
            if (result == 0) {
                copy_bytes(
                    (void *)(uintptr_t)arm64_mmu_kernel_address(
                        destination_page),
                    (const void *)(uintptr_t)arm64_mmu_kernel_address(
                        source_mapping->physical_address),
                    PAGE_SIZE);
                if ((flags & VMA_EXEC) != 0)
                    arm64_mmu_sync_code(
                        arm64_mmu_kernel_address(destination_page),
                        PAGE_SIZE);
            }
        }
        if (result != 0)
            goto failed;

        destination_index = arm64_user_vm_mapping_index(
            destination, source_mapping->vma.start);
        if (destination_index == destination->mapping_count)
            goto failed;
        destination_mapping = &destination->mappings[destination_index];
        destination_mapping->vma.shm_id = source_mapping->vma.shm_id;
    }

    destination->space.brk = source->space.brk;
    if (arm64_user_vm_validate_identity(destination) != 0)
        goto failed;
    return 0;

failed:
    (void)arm64_user_vm_destroy(destination, allocator);
    return -3;
}

int arm64_user_vm_map_new_page(arm64_user_vm_t *vm,
                               early_page_allocator_t *allocator,
                               vaddr_t virtual_address,
                               unsigned int flags,
                               paddr_t *physical_address)
{
    paddr_t page;
    paddr_t l3_address;
    unsigned int index;
    int result;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator ||
        !physical_address ||
        (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        virtual_address >= (1ULL << 39) ||
        !arm64_user_vm_flags_valid(flags) || (flags & VMA_LAZY) != 0 ||
        vm->mapping_count >= ARM64_USER_VM_MAX_MAPPINGS)
        return -1;

    if (arm64_user_vm_mapping_index(vm, virtual_address) !=
        vm->mapping_count)
        return -2;

    if (arm64_user_vm_ensure_l3(vm, allocator, virtual_address,
                                &l3_address) != 0) {
        arm64_user_vm_reclaim_empty_tables(vm, allocator,
                                           virtual_address);
        return -3;
    }
    if (early_page_alloc_pages(allocator, 1, &page) != 0) {
        arm64_user_vm_reclaim_empty_tables(vm, allocator,
                                           virtual_address);
        return -4;
    }

    result = arm64_mmu_map_user_l3_page(l3_address, virtual_address,
                                        page, flags, vm->asid);
    if (result != 0) {
        early_page_free_pages(allocator, page, 1);
        arm64_user_vm_reclaim_empty_tables(vm, allocator,
                                           virtual_address);
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
    vm->tlb_generation = allocate_tlb_generation();
    arm64_user_vm_publish_targeted_generation(vm);
    *physical_address = page;
    return 0;
}

int arm64_user_vm_unmap_page(arm64_user_vm_t *vm,
                             early_page_allocator_t *allocator,
                             vaddr_t virtual_address)
{
    arm64_user_vm_l3_table_t *l3;
    paddr_t physical_address;
    arm64_mmu_u64 descriptor_address;
    unsigned int index;
    unsigned int last;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator ||
        (virtual_address & PAGE_OFFSET_MASK) != 0)
        return -1;
    index = arm64_user_vm_mapping_index(vm, virtual_address);
    if (index == vm->mapping_count)
        return -2;
    if (vm->mappings[index].physical_address == 0) {
        last = vm->mapping_count - 1;
        if (index != last)
            vm->mappings[index] = vm->mappings[last];
        clear_bytes(&vm->mappings[last], sizeof(vm->mappings[last]));
        vm->mapping_count--;
        arm64_user_vm_rebuild_vma_list(vm);
        return arm64_user_vm_validate_identity(vm);
    }
    l3 = arm64_user_vm_find_l3(vm, virtual_address);
    if (!l3)
        return -3;
    if (arm64_mmu_unmap_user_l3_page(l3->table, virtual_address,
                                     vm->asid,
                                     &descriptor_address) != 0)
        return -4;
    physical_address = (paddr_t)descriptor_address;
    if (physical_address != vm->mappings[index].physical_address)
        return -5;
    if (early_page_free_pages(allocator, physical_address, 1) != 0)
        return -6;

    last = vm->mapping_count - 1;
    if (index != last)
        vm->mappings[index] = vm->mappings[last];
    clear_bytes(&vm->mappings[last], sizeof(vm->mappings[last]));
    vm->mapping_count--;
    arm64_user_vm_rebuild_vma_list(vm);
    vm->tlb_generation = allocate_tlb_generation();
    arm64_user_vm_publish_targeted_generation(vm);
    if (arm64_user_vm_reclaim_empty_tables(vm, allocator,
                                           virtual_address) != 0)
        return -7;
    return arm64_user_vm_validate_identity(vm);
}

int arm64_user_vm_map_anonymous(arm64_user_vm_t *vm,
                                early_page_allocator_t *allocator,
                                vaddr_t virtual_address,
                                size_t length,
                                unsigned int flags)
{
    paddr_t page;
    vaddr_t end;
    vaddr_t cursor;
    unsigned int mapped = 0;
    unsigned int page_count;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator ||
        length == 0 || (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        (length & PAGE_OFFSET_MASK) != 0 ||
        !arm64_user_vm_flags_valid(flags))
        return -1;
    end = virtual_address + (vaddr_t)length;
    if (end <= virtual_address || end > (1ULL << 39))
        return -1;
    page_count = (unsigned int)(length / PAGE_SIZE);
    if (page_count > ARM64_USER_VM_MAX_MAPPINGS - vm->mapping_count)
        return -2;

    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        if (arm64_user_vm_mapping_index(vm, cursor) != vm->mapping_count)
            return -2;
    }
    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        if (arm64_user_vm_map_new_page(vm, allocator, cursor,
                                       flags, &page) != 0)
            break;
        mapped++;
    }
    if (cursor == end)
        return 0;

    while (mapped > 0) {
        mapped--;
        cursor = virtual_address + (vaddr_t)mapped * PAGE_SIZE;
        if (arm64_user_vm_unmap_page(vm, allocator, cursor) != 0)
            return -4;
    }
    return -3;
}

int arm64_user_vm_unmap_range(arm64_user_vm_t *vm,
                              early_page_allocator_t *allocator,
                              vaddr_t virtual_address,
                              size_t length)
{
    vaddr_t end;
    vaddr_t cursor;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator ||
        length == 0 || (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        (length & PAGE_OFFSET_MASK) != 0)
        return -1;
    end = virtual_address + (vaddr_t)length;
    if (end <= virtual_address || end > (1ULL << 39))
        return -1;

    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        if (arm64_user_vm_mapping_index(vm, cursor) == vm->mapping_count)
            return -2;
    }
    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        if (arm64_user_vm_unmap_page(vm, allocator, cursor) != 0)
            return -3;
    }
    return 0;
}

int arm64_user_vm_reserve_anonymous(arm64_user_vm_t *vm,
                                    vaddr_t virtual_address,
                                    size_t length,
                                    unsigned int flags)
{
    vaddr_t cursor;
    vaddr_t end;
    unsigned int reserved = 0;
    unsigned int page_count;

    flags |= VMA_LAZY;
    if (arm64_user_vm_validate_identity(vm) != 0 || length == 0 ||
        (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        (length & PAGE_OFFSET_MASK) != 0 ||
        !arm64_user_vm_flags_valid(flags) || (flags & VMA_EXEC) != 0)
        return -1;
    end = virtual_address + (vaddr_t)length;
    if (end <= virtual_address || end > (1ULL << 39))
        return -1;
    page_count = (unsigned int)(length / PAGE_SIZE);
    if (page_count > ARM64_USER_VM_MAX_MAPPINGS - vm->mapping_count)
        return -2;
    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        if (arm64_user_vm_mapping_index(vm, cursor) != vm->mapping_count)
            return -2;
    }

    for (cursor = virtual_address; cursor < end; cursor += PAGE_SIZE) {
        unsigned int index = vm->mapping_count++;

        vm->mappings[index].vma.start = cursor;
        vm->mappings[index].vma.end = cursor + PAGE_SIZE;
        vm->mappings[index].vma.flags = flags;
        vm->mappings[index].vma.shm_id = 0;
        vm->mappings[index].vma.next = NULL;
        vm->mappings[index].physical_address = 0;
        reserved++;
    }
    arm64_user_vm_rebuild_vma_list(vm);
    if (arm64_user_vm_validate_identity(vm) == 0)
        return 0;

    while (reserved-- > 0)
        clear_bytes(&vm->mappings[--vm->mapping_count],
                    sizeof(vm->mappings[0]));
    arm64_user_vm_rebuild_vma_list(vm);
    return -3;
}

int arm64_user_vm_handle_page_fault(arm64_user_vm_t *vm,
                                    early_page_allocator_t *allocator,
                                    vaddr_t fault_address,
                                    int is_write,
                                    int is_execute,
                                    paddr_t *physical_address)
{
    vaddr_t page_address = fault_address & PAGE_MASK;
    arm64_user_vm_mapping_t *mapping;
    paddr_t page;
    paddr_t l3_address;
    unsigned int index;
    unsigned int page_flags;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator)
        return -1;
    index = arm64_user_vm_mapping_index(vm, page_address);
    if (index == vm->mapping_count)
        return -2;
    mapping = &vm->mappings[index];
    if (mapping->physical_address != 0 ||
        (mapping->vma.flags & VMA_LAZY) == 0 ||
        (is_write && (mapping->vma.flags & VMA_WRITE) == 0) ||
        (is_execute && (mapping->vma.flags & VMA_EXEC) == 0))
        return -3;
    if (arm64_user_vm_ensure_l3(vm, allocator, page_address,
                                &l3_address) != 0)
        return -4;
    if (early_page_alloc_pages(allocator, 1, &page) != 0) {
        arm64_user_vm_reclaim_empty_tables(vm, allocator, page_address);
        return -5;
    }
    clear_bytes((void *)(uintptr_t)arm64_mmu_kernel_address(page), PAGE_SIZE);
    page_flags = mapping->vma.flags &
        (VMA_READ | VMA_WRITE | VMA_EXEC);
    if (arm64_mmu_map_user_l3_page(l3_address, page_address, page,
                                   page_flags, vm->asid) != 0) {
        early_page_free_pages(allocator, page, 1);
        arm64_user_vm_reclaim_empty_tables(vm, allocator, page_address);
        return -6;
    }
    mapping->physical_address = page;
    mapping->vma.flags = page_flags;
    vm->tlb_generation = allocate_tlb_generation();
    arm64_user_vm_publish_targeted_generation(vm);
    if (physical_address)
        *physical_address = page;
    return arm64_user_vm_validate_identity(vm);
}

int arm64_user_vm_set_brk(arm64_user_vm_t *vm,
                          early_page_allocator_t *allocator,
                          vaddr_t requested,
                          vaddr_t *result)
{
    vaddr_t old_break;
    vaddr_t old_end;
    vaddr_t new_end;

    if (arm64_user_vm_validate_identity(vm) != 0 || !allocator || !result)
        return -1;
    if (requested == 0) {
        *result = vm->space.brk;
        return 0;
    }
    if (requested < vm->space.heap_start || requested > vm->space.heap_end)
        return -2;
    old_break = vm->space.brk;
    old_end = (old_break + PAGE_SIZE - 1) & PAGE_MASK;
    new_end = (requested + PAGE_SIZE - 1) & PAGE_MASK;
    if (new_end > old_end) {
        if (arm64_user_vm_reserve_anonymous(
                vm, old_end, new_end - old_end,
                VMA_READ | VMA_WRITE) != 0)
            return -3;
    } else if (new_end < old_end) {
        if (arm64_user_vm_unmap_range(vm, allocator, new_end,
                                      old_end - new_end) != 0)
            return -4;
    }
    vm->space.brk = requested;
    *result = requested;
    return 0;
}

int arm64_user_vm_mmap_anonymous(arm64_user_vm_t *vm,
                                 vaddr_t hint,
                                 size_t length,
                                 unsigned int flags,
                                 vaddr_t *result)
{
    vaddr_t cursor;
    vaddr_t end;
    const vma_t *vma;

    if (arm64_user_vm_validate_identity(vm) != 0 || !result || length == 0 ||
        !arm64_user_vm_flags_valid(flags) || (flags & VMA_EXEC) != 0)
        return -1;
    length = (length + PAGE_SIZE - 1) & PAGE_MASK;
    if (length == 0 || length >
        (size_t)(USER_STACK_BOTTOM - USER_SHM_END))
        return -2;
    cursor = hint ? (hint & PAGE_MASK) : USER_SHM_END;
    if (cursor < USER_SHM_END || cursor >= USER_STACK_BOTTOM)
        cursor = USER_SHM_END;

    while (cursor < USER_STACK_BOTTOM) {
        end = cursor + (vaddr_t)length;
        if (end <= cursor || end > USER_STACK_BOTTOM)
            return -3;
        for (vma = vm->space.vma_list; vma; vma = vma->next) {
            if (vma->end <= cursor)
                continue;
            if (vma->start >= end)
                break;
            cursor = vma->end;
            break;
        }
        if (!vma || vma->start >= end) {
            if (arm64_user_vm_reserve_anonymous(vm, cursor, length,
                                                flags) != 0)
                return -4;
            *result = cursor;
            return 0;
        }
    }
    return -5;
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
        paddr_t physical_address;

        if (arm64_user_vm_lookup(vm, page, &physical_address, &flags) != 0 ||
            physical_address == 0 ||
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
        if (vm->mappings[index].physical_address != 0 &&
            early_page_free_pages(allocator,
                                  vm->mappings[index].physical_address,
                                  1) != 0)
            return -3;
    }
    for (index = 0; index < vm->l3_table_count; index++) {
        if (early_page_free_pages(allocator,
                                  vm->l3_tables[index].table, 1) != 0)
            return -4;
    }
    for (index = 0; index < vm->l2_table_count; index++) {
        if (early_page_free_pages(allocator,
                                  vm->l2_tables[index].table, 1) != 0)
            return -5;
    }
    if (early_page_free_pages(allocator, vm->l1, 1) != 0)
        return -6;

    release_asid(vm->asid);
    clear_bytes(vm, sizeof(*vm));
    return 0;
}

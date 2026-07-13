/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-CPU ownership wrapper around the first ARM64 user page tables.
 */

#include <asm/mmu.h>
#include <asm/user_vm.h>

#define ARM64_ASID_COUNT       256u
#define ARM64_ASID_BITMAP_SIZE (ARM64_ASID_COUNT / 8u)
#define ARM64_L3_WINDOW_SIZE   0x200000ULL
#define ARM64_TTBR_TABLE_MASK  0x0000FFFFFFFFF000ULL

static uint8_t arm64_asid_bitmap[ARM64_ASID_BITMAP_SIZE];

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

    if (!vm || !allocator || !physical_address || vm->asid == 0 ||
        (virtual_address & PAGE_OFFSET_MASK) != 0 ||
        vm->mapping_count >= ARM64_USER_VM_MAX_MAPPINGS)
        return -1;

    window = virtual_address & ~(ARM64_L3_WINDOW_SIZE - 1u);
    if (vm->mapping_count != 0 && window != vm->l3_window)
        return -2;
    for (index = 0; index < vm->mapping_count; index++) {
        if (vm->mappings[index].virtual_address == virtual_address)
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
    vm->mappings[index].virtual_address = virtual_address;
    vm->mappings[index].physical_address = page;
    vm->mappings[index].flags = flags;
    vm->l3_window = window;
    *physical_address = page;
    return 0;
}

int arm64_user_vm_activate(const arm64_user_vm_t *vm)
{
    if (!vm || vm->asid == 0 || vm->l1 == 0)
        return -1;
    return arm64_mmu_switch_user_ttbr0(vm->l1, vm->asid);
}

int arm64_user_vm_lookup(const arm64_user_vm_t *vm,
                         vaddr_t virtual_address,
                         paddr_t *physical_address,
                         unsigned int *flags)
{
    unsigned int index;

    if (!vm)
        return -1;
    for (index = 0; index < vm->mapping_count; index++) {
        if (vm->mappings[index].virtual_address != virtual_address)
            continue;
        if (physical_address)
            *physical_address = vm->mappings[index].physical_address;
        if (flags)
            *flags = vm->mappings[index].flags;
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

    if (!vm || required_flags == 0 ||
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

int arm64_user_vm_destroy(arm64_user_vm_t *vm,
                          early_page_allocator_t *allocator)
{
    unsigned int index;

    if (!vm || !allocator || vm->asid == 0 || vm->l1 == 0)
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

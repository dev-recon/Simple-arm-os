/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/mmu/mmu.c
 * Layer: ARM64 / memory management
 *
 * Responsibilities:
 * - Build and activate ARMv8-A 4 KiB translation tables for QEMU virt.
 * - Grow user L2/L3 hierarchies and map or unmap individual pages.
 * - Enforce kernel/user page permissions and targeted TLB maintenance.
 * - Provide conservative and resident-ASID TTBR0 activation primitives.
 *
 * Notes:
 * - Address-space ownership and ASID generations are managed by user_vm.c.
 */

#include <asm/mmu.h>

typedef unsigned long long uint64_t;

#define ARM64_L1_ENTRIES 512u
#define ARM64_L1_BLOCK_SIZE (1ULL << 30)
#define ARM64_L2_BLOCK_SIZE (1ULL << 21)
#define ARM64_TABLE_MASK 0x0000FFFFFFFFF000ULL
#define ARM64_QEMU_RAM_BASE 0x40000000ULL
#define ARM64_L3_WINDOW_END (ARM64_QEMU_RAM_BASE + ARM64_L2_BLOCK_SIZE)

#define DESC_VALID       (1ULL << 0)
#define DESC_TABLE_PAGE  (1ULL << 1)
#define DESC_ATTR_INDEX(n) ((uint64_t)(n) << 2)
#define DESC_AF          (1ULL << 10)
#define DESC_AP_RO_EL1   (2ULL << 6)
#define DESC_AP_RW_EL0   (1ULL << 6)
#define DESC_AP_RO_EL0   (3ULL << 6)
#define DESC_SH_OUTER    (2ULL << 8)
#define DESC_SH_INNER    (3ULL << 8)
#define DESC_PXN         (1ULL << 53)
#define DESC_UXN         (1ULL << 54)

#define MAIR_ATTR_DEVICE_NGNRE 0x04ULL
#define MAIR_ATTR_NORMAL_WBWA  0xffULL

#define TCR_T0SZ_39BIT   25ULL
#define TCR_IRGN0_WBWA   (1ULL << 8)
#define TCR_ORGN0_WBWA   (1ULL << 10)
#define TCR_SH0_INNER    (3ULL << 12)
#define TCR_EPD1         (1ULL << 23)
#define TCR_T1SZ_39BIT   (25ULL << 16)
#define TCR_IRGN1_WBWA   (1ULL << 24)
#define TCR_ORGN1_WBWA   (1ULL << 26)
#define TCR_SH1_INNER    (3ULL << 28)
#define TCR_TG1_4K       (2ULL << 30)
#define TCR_TTBR1_FIELDS (0xFFFFULL << 16)
#define TCR_IPS_SHIFT    32u

#define SCTLR_M          (1ULL << 0)
#define SCTLR_C          (1ULL << 2)
#define SCTLR_SA         (1ULL << 3)
#define SCTLR_SA0        (1ULL << 4)
#define SCTLR_I          (1ULL << 12)

#define TTBR_ASID_SHIFT  48u
#define TTBR_ASID_MAX    255u

static uint64_t arm64_l1_table[ARM64_L1_ENTRIES]
    __attribute__((aligned(4096)));

static inline void arm64_dsb_sy(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline void arm64_isb(void)
{
    __asm__ volatile("isb" ::: "memory");
}

static void populate_identity_l1(uint64_t *table)
{
    unsigned int i;

    for (i = 0; i < ARM64_L1_ENTRIES; i++)
        table[i] = 0;

    /* 0x00000000-0x3fffffff: QEMU virt MMIO, never executable. */
    table[0] =
        DESC_VALID |
        DESC_ATTR_INDEX(0) |
        DESC_AF |
        DESC_SH_OUTER |
        DESC_PXN |
        DESC_UXN;

    /* 0x40000000-0x7fffffff: QEMU RAM containing kernel, stack and DTB. */
    table[1] =
        ARM64_L1_BLOCK_SIZE |
        DESC_VALID |
        DESC_ATTR_INDEX(1) |
        DESC_AF |
        DESC_SH_INNER;
}

static void clean_range_to_poc(void *start, uint64_t length)
{
    uint64_t ctr;
    uint64_t line_size;
    uint64_t address;
    uint64_t end = (uint64_t)start + length;

    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    line_size = 4ULL << ((ctr >> 16) & 0xfu);
    address = (uint64_t)start & ~(line_size - 1u);

    while (address < end) {
        __asm__ volatile("dc cvac, %0" :: "r"(address) : "memory");
        address += line_size;
    }
    __asm__ volatile("dsb ish" ::: "memory");
}

static int table_address_valid(uint64_t address)
{
    return (address & 0xfffu) == 0 &&
           (address & ~ARM64_TABLE_MASK) == 0;
}

static uint64_t normal_memory_descriptor(uint64_t address, int page)
{
    uint64_t descriptor =
        (address & ARM64_TABLE_MASK) |
        DESC_VALID |
        DESC_ATTR_INDEX(1) |
        DESC_AF |
        DESC_SH_INNER |
        DESC_PXN |
        DESC_UXN;

    if (page)
        descriptor |= DESC_TABLE_PAGE;
    return descriptor;
}

static uint64_t device_block_descriptor(void)
{
    return DESC_VALID |
           DESC_ATTR_INDEX(0) |
           DESC_AF |
           DESC_SH_OUTER |
           DESC_PXN |
           DESC_UXN;
}

static int user_page_flags_valid(unsigned int flags)
{
    if ((flags & ARM64_USER_PAGE_READ) == 0 ||
        (flags & ~(ARM64_USER_PAGE_READ |
                   ARM64_USER_PAGE_WRITE |
                   ARM64_USER_PAGE_EXEC)) != 0)
        return 0;
    return (flags & (ARM64_USER_PAGE_WRITE | ARM64_USER_PAGE_EXEC)) !=
           (ARM64_USER_PAGE_WRITE | ARM64_USER_PAGE_EXEC);
}

static void invalidate_user_page(uint64_t virtual_address,
                                 unsigned int asid)
{
    uint64_t operand = ((uint64_t)asid << TTBR_ASID_SHIFT) |
                       (virtual_address >> 12);

    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("tlbi vae1, %0" :: "r"(operand));
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
}

static int user_table_is_empty(uint64_t table_address)
{
    uint64_t *table =
        (uint64_t *)arm64_mmu_kernel_address(table_address);
    unsigned int index;

    for (index = 0; index < ARM64_L1_ENTRIES; index++) {
        if ((table[index] & DESC_VALID) != 0)
            return 0;
    }
    return 1;
}

static int remove_user_table(uint64_t parent_address,
                             uint64_t child_address,
                             uint64_t parent_index,
                             uint64_t virtual_address,
                             unsigned int asid)
{
    uint64_t *parent =
        (uint64_t *)arm64_mmu_kernel_address(parent_address);
    uint64_t descriptor = parent[parent_index];

    if ((descriptor & (DESC_VALID | DESC_TABLE_PAGE)) !=
            (DESC_VALID | DESC_TABLE_PAGE) ||
        (descriptor & ARM64_TABLE_MASK) != child_address)
        return -1;
    if (!user_table_is_empty(child_address))
        return -2;

    parent[parent_index] = 0;
    clean_range_to_poc(&parent[parent_index],
                       sizeof(parent[parent_index]));
    invalidate_user_page(virtual_address, asid);
    return 0;
}

static uint64_t user_page_descriptor(uint64_t physical_address,
                                     unsigned int flags)
{
    uint64_t descriptor =
        (physical_address & ARM64_TABLE_MASK) |
        DESC_VALID | DESC_TABLE_PAGE |
        DESC_ATTR_INDEX(1) | DESC_AF | DESC_SH_INNER |
        DESC_PXN;

    if (flags & ARM64_USER_PAGE_WRITE)
        descriptor |= DESC_AP_RW_EL0;
    else
        descriptor |= DESC_AP_RO_EL0;
    if ((flags & ARM64_USER_PAGE_EXEC) == 0)
        descriptor |= DESC_UXN;
    return descriptor;
}

arm64_mmu_u64 arm64_mmu_kernel_address(arm64_mmu_u64 physical_address)
{
    uint64_t pc;

    __asm__ volatile("adr %0, ." : "=r"(pc));
    if (pc >= ARM64_KERNEL_VA_BASE)
        return ARM64_KERNEL_VA_BASE + physical_address;
    return physical_address;
}

arm64_mmu_u64 arm64_mmu_read_sctlr(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(value));
    return value;
}

arm64_mmu_u64 arm64_mmu_read_tcr(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(value));
    return value;
}

arm64_mmu_u64 arm64_mmu_read_ttbr0(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(value));
    return value;
}

arm64_mmu_u64 arm64_mmu_read_ttbr1(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(value));
    return value;
}

arm64_mmu_u64 arm64_mmu_translate_read(arm64_mmu_u64 address)
{
    uint64_t result;

    __asm__ volatile("at s1e1r, %0" :: "r"(address));
    arm64_isb();
    __asm__ volatile("mrs %0, par_el1" : "=r"(result));
    return result;
}

arm64_mmu_u64 arm64_mmu_translate_write(arm64_mmu_u64 address)
{
    uint64_t result;

    __asm__ volatile("at s1e1w, %0" :: "r"(address));
    arm64_isb();
    __asm__ volatile("mrs %0, par_el1" : "=r"(result));
    return result;
}

arm64_mmu_u64 arm64_mmu_translate_user_read(arm64_mmu_u64 address)
{
    uint64_t result;

    __asm__ volatile("at s1e0r, %0" :: "r"(address));
    arm64_isb();
    __asm__ volatile("mrs %0, par_el1" : "=r"(result));
    return result;
}

arm64_mmu_u64 arm64_mmu_translate_user_write(arm64_mmu_u64 address)
{
    uint64_t result;

    __asm__ volatile("at s1e0w, %0" :: "r"(address));
    arm64_isb();
    __asm__ volatile("mrs %0, par_el1" : "=r"(result));
    return result;
}

int arm64_mmu_enable_identity_map(void)
{
    uint64_t mmfr0;
    uint64_t parange;
    uint64_t tgran4;
    uint64_t mair;
    uint64_t tcr;
    uint64_t sctlr;

    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    parange = mmfr0 & 0xfu;
    tgran4 = (mmfr0 >> 28) & 0xfu;

    if (tgran4 == 0xfu || parange > 6u)
        return -1;

    populate_identity_l1(arm64_l1_table);

    mair = MAIR_ATTR_DEVICE_NGNRE |
           (MAIR_ATTR_NORMAL_WBWA << 8);
    tcr = TCR_T0SZ_39BIT |
          TCR_IRGN0_WBWA |
          TCR_ORGN0_WBWA |
          TCR_SH0_INNER |
          TCR_EPD1 |
          (parange << TCR_IPS_SHIFT);

    sctlr = arm64_mmu_read_sctlr();
    if (sctlr & SCTLR_M)
        return -2;

    arm64_dsb_sy();
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"((uint64_t)arm64_l1_table));
    arm64_isb();

    __asm__ volatile("tlbi vmalle1");
    arm64_dsb_sy();
    arm64_isb();

    sctlr |= SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_SA | SCTLR_SA0;
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr) : "memory");
    arm64_isb();

    return 0;
}

int arm64_mmu_prepare_identity_tables(arm64_mmu_u64 l1_address,
                                      arm64_mmu_u64 l2_address,
                                      arm64_mmu_u64 l3_address)
{
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    unsigned int i;

    if (!table_address_valid(l1_address) ||
        !table_address_valid(l2_address) ||
        !table_address_valid(l3_address) ||
        l1_address == l2_address || l1_address == l3_address ||
        l2_address == l3_address)
        return -1;

    l1 = (uint64_t *)arm64_mmu_kernel_address(l1_address);
    l2 = (uint64_t *)arm64_mmu_kernel_address(l2_address);
    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    for (i = 0; i < ARM64_L1_ENTRIES; i++) {
        l1[i] = 0;
        l2[i] = normal_memory_descriptor(
            ARM64_QEMU_RAM_BASE + (uint64_t)i * ARM64_L2_BLOCK_SIZE,
            0);
        l3[i] = normal_memory_descriptor(
            ARM64_QEMU_RAM_BASE + (uint64_t)i * 4096u,
            1);
    }

    l1[0] =
        DESC_VALID |
        DESC_ATTR_INDEX(0) |
        DESC_AF |
        DESC_SH_OUTER |
        DESC_PXN |
        DESC_UXN;
    l1[1] = (l2_address & ARM64_TABLE_MASK) |
            DESC_VALID | DESC_TABLE_PAGE;
    l2[0] = (l3_address & ARM64_TABLE_MASK) |
            DESC_VALID | DESC_TABLE_PAGE;

    clean_range_to_poc(l1, 4096u);
    clean_range_to_poc(l2, 4096u);
    clean_range_to_poc(l3, 4096u);
    return 0;
}

int arm64_mmu_switch_ttbr0(arm64_mmu_u64 table_address)
{
    if (!table_address_valid(table_address))
        return -1;
    if ((arm64_mmu_read_sctlr() & SCTLR_M) == 0)
        return -2;

    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(table_address) : "memory");
    arm64_isb();
    __asm__ volatile("tlbi vmalle1");
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
    return 0;
}

int arm64_mmu_update_identity_page(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 address,
                                   int present)
{
    uint64_t *l3;
    uint64_t index;
    uint64_t operand;

    if (!table_address_valid(l3_address) ||
        (address & 0xfffu) != 0 ||
        address < ARM64_QEMU_RAM_BASE || address >= ARM64_L3_WINDOW_END)
        return -1;

    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    index = (address - ARM64_QEMU_RAM_BASE) >> 12;
    l3[index] = present ? normal_memory_descriptor(address, 1) : 0;
    clean_range_to_poc(&l3[index], sizeof(l3[index]));

    operand = address >> 12;
    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("tlbi vae1, %0" :: "r"(operand));
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
    return 0;
}

int arm64_mmu_protect_kernel_image(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 text_start,
                                   arm64_mmu_u64 text_end,
                                   arm64_mmu_u64 rodata_start,
                                   arm64_mmu_u64 rodata_end)
{
    uint64_t *l3;
    uint64_t address;
    uint64_t index;

    if (!table_address_valid(l3_address) ||
        text_start >= text_end || rodata_start >= rodata_end ||
        (text_start & 0xfffu) != 0 || (text_end & 0xfffu) != 0 ||
        (rodata_start & 0xfffu) != 0 || (rodata_end & 0xfffu) != 0 ||
        text_start < ARM64_QEMU_RAM_BASE ||
        rodata_end > ARM64_L3_WINDOW_END)
        return -1;

    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    for (address = text_start; address < text_end; address += 4096u) {
        index = (address - ARM64_QEMU_RAM_BASE) >> 12;
        l3[index] =
            (address & ARM64_TABLE_MASK) |
            DESC_VALID | DESC_TABLE_PAGE |
            DESC_ATTR_INDEX(1) | DESC_AF | DESC_SH_INNER |
            DESC_AP_RO_EL1 | DESC_UXN;
    }
    for (address = rodata_start; address < rodata_end; address += 4096u) {
        index = (address - ARM64_QEMU_RAM_BASE) >> 12;
        l3[index] =
            (address & ARM64_TABLE_MASK) |
            DESC_VALID | DESC_TABLE_PAGE |
            DESC_ATTR_INDEX(1) | DESC_AF | DESC_SH_INNER |
            DESC_AP_RO_EL1 | DESC_PXN | DESC_UXN;
    }

    clean_range_to_poc(l3, 4096u);
    return 0;
}

int arm64_mmu_install_ttbr1(arm64_mmu_u64 l1_address,
                            arm64_mmu_u64 shared_l2_address)
{
    uint64_t *l1;
    uint64_t tcr;
    unsigned int i;

    if (!table_address_valid(l1_address) ||
        !table_address_valid(shared_l2_address) ||
        l1_address == shared_l2_address)
        return -1;
    if ((arm64_mmu_read_sctlr() & SCTLR_M) == 0)
        return -2;

    l1 = (uint64_t *)arm64_mmu_kernel_address(l1_address);
    for (i = 0; i < ARM64_L1_ENTRIES; i++)
        l1[i] = 0;
    l1[0] = device_block_descriptor();
    l1[1] = (shared_l2_address & ARM64_TABLE_MASK) |
            DESC_VALID | DESC_TABLE_PAGE;
    clean_range_to_poc(l1, 4096u);

    tcr = arm64_mmu_read_tcr();
    tcr &= ~TCR_TTBR1_FIELDS;
    tcr |= TCR_T1SZ_39BIT |
           TCR_IRGN1_WBWA |
           TCR_ORGN1_WBWA |
           TCR_SH1_INNER |
           TCR_TG1_4K;

    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("msr ttbr1_el1, %0" :: "r"(l1_address) : "memory");
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr) : "memory");
    arm64_isb();
    __asm__ volatile("tlbi vmalle1");
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
    return 0;
}

int arm64_mmu_retire_low_map(arm64_mmu_u64 ttbr0_l1_address)
{
    uint64_t *l1;

    if (!table_address_valid(ttbr0_l1_address) ||
        (arm64_mmu_read_ttbr0() & ARM64_TABLE_MASK) != ttbr0_l1_address)
        return -1;
    if ((arm64_mmu_read_ttbr1() & ARM64_TABLE_MASK) == 0)
        return -2;

    l1 = (uint64_t *)arm64_mmu_kernel_address(ttbr0_l1_address);
    if ((l1[0] & DESC_VALID) == 0 ||
        (l1[1] & (DESC_VALID | DESC_TABLE_PAGE)) !=
        (DESC_VALID | DESC_TABLE_PAGE))
        return -3;

    l1[0] = 0;
    l1[1] = 0;
    clean_range_to_poc(&l1[0], 2 * sizeof(l1[0]));

    __asm__ volatile("dsb ishst" ::: "memory");
    __asm__ volatile("tlbi vmalle1");
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
    return 0;
}

int arm64_mmu_prepare_empty_ttbr0(arm64_mmu_u64 l1_address)
{
    uint64_t *l1;
    unsigned int i;

    if (!table_address_valid(l1_address))
        return -1;

    l1 = (uint64_t *)arm64_mmu_kernel_address(l1_address);
    for (i = 0; i < ARM64_L1_ENTRIES; i++)
        l1[i] = 0;
    clean_range_to_poc(l1, 4096u);
    return 0;
}

int arm64_mmu_prepare_user_page(arm64_mmu_u64 l1_address,
                                arm64_mmu_u64 l2_address,
                                arm64_mmu_u64 l3_address,
                                arm64_mmu_u64 virtual_address,
                                arm64_mmu_u64 physical_address,
                                unsigned int flags)
{
    uint64_t *l1;
    uint64_t *l2;
    uint64_t *l3;
    uint64_t l1_index;
    uint64_t l2_index;
    uint64_t l3_index;
    unsigned int i;

    if (!table_address_valid(l1_address) ||
        !table_address_valid(l2_address) ||
        !table_address_valid(l3_address) ||
        l1_address == l2_address || l1_address == l3_address ||
        l2_address == l3_address ||
        (virtual_address & 0xfffu) != 0 ||
        (physical_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) ||
        !user_page_flags_valid(flags))
        return -1;

    l1 = (uint64_t *)arm64_mmu_kernel_address(l1_address);
    l2 = (uint64_t *)arm64_mmu_kernel_address(l2_address);
    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    for (i = 0; i < ARM64_L1_ENTRIES; i++) {
        l1[i] = 0;
        l2[i] = 0;
        l3[i] = 0;
    }

    l1_index = (virtual_address >> 30) & 0x1ffu;
    l2_index = (virtual_address >> 21) & 0x1ffu;
    l3_index = (virtual_address >> 12) & 0x1ffu;
    l1[l1_index] = (l2_address & ARM64_TABLE_MASK) |
                   DESC_VALID | DESC_TABLE_PAGE;
    l2[l2_index] = (l3_address & ARM64_TABLE_MASK) |
                   DESC_VALID | DESC_TABLE_PAGE;
    l3[l3_index] = user_page_descriptor(physical_address, flags);

    clean_range_to_poc(l1, 4096u);
    clean_range_to_poc(l2, 4096u);
    clean_range_to_poc(l3, 4096u);
    return 0;
}

int arm64_mmu_prepare_user_l3_page(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 virtual_address,
                                   arm64_mmu_u64 physical_address,
                                   unsigned int flags)
{
    uint64_t *l3;
    uint64_t l3_index;

    if (!table_address_valid(l3_address) ||
        (virtual_address & 0xfffu) != 0 ||
        (physical_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) ||
        !user_page_flags_valid(flags))
        return -1;

    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    l3_index = (virtual_address >> 12) & 0x1ffu;
    l3[l3_index] = user_page_descriptor(physical_address, flags);
    clean_range_to_poc(&l3[l3_index], sizeof(l3[l3_index]));
    return 0;
}

int arm64_mmu_install_user_l2(arm64_mmu_u64 l1_address,
                              arm64_mmu_u64 l2_address,
                              arm64_mmu_u64 virtual_address)
{
    uint64_t *l1;
    uint64_t *l2;
    uint64_t l1_index;
    unsigned int index;

    if (!table_address_valid(l1_address) ||
        !table_address_valid(l2_address) || l1_address == l2_address ||
        virtual_address >= (1ULL << 39))
        return -1;

    l1 = (uint64_t *)arm64_mmu_kernel_address(l1_address);
    l2 = (uint64_t *)arm64_mmu_kernel_address(l2_address);
    l1_index = (virtual_address >> 30) & 0x1ffu;
    if ((l1[l1_index] & DESC_VALID) != 0)
        return -2;

    for (index = 0; index < ARM64_L1_ENTRIES; index++)
        l2[index] = 0;
    l1[l1_index] = (l2_address & ARM64_TABLE_MASK) |
                   DESC_VALID | DESC_TABLE_PAGE;
    clean_range_to_poc(l2, 4096u);
    clean_range_to_poc(&l1[l1_index], sizeof(l1[l1_index]));
    return 0;
}

int arm64_mmu_install_user_l3(arm64_mmu_u64 l2_address,
                              arm64_mmu_u64 l3_address,
                              arm64_mmu_u64 virtual_address)
{
    uint64_t *l2;
    uint64_t *l3;
    uint64_t l2_index;
    unsigned int index;

    if (!table_address_valid(l2_address) ||
        !table_address_valid(l3_address) || l2_address == l3_address ||
        virtual_address >= (1ULL << 39))
        return -1;

    l2 = (uint64_t *)arm64_mmu_kernel_address(l2_address);
    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    l2_index = (virtual_address >> 21) & 0x1ffu;
    if ((l2[l2_index] & DESC_VALID) != 0)
        return -2;

    for (index = 0; index < ARM64_L1_ENTRIES; index++)
        l3[index] = 0;
    l2[l2_index] = (l3_address & ARM64_TABLE_MASK) |
                   DESC_VALID | DESC_TABLE_PAGE;
    clean_range_to_poc(l3, 4096u);
    clean_range_to_poc(&l2[l2_index], sizeof(l2[l2_index]));
    return 0;
}

int arm64_mmu_map_user_l3_page(arm64_mmu_u64 l3_address,
                               arm64_mmu_u64 virtual_address,
                               arm64_mmu_u64 physical_address,
                               unsigned int flags,
                               unsigned int asid)
{
    uint64_t *l3;
    uint64_t l3_index;

    if (!table_address_valid(l3_address) ||
        (virtual_address & 0xfffu) != 0 ||
        (physical_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) ||
        !user_page_flags_valid(flags) || asid == 0 ||
        asid > TTBR_ASID_MAX)
        return -1;

    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    l3_index = (virtual_address >> 12) & 0x1ffu;
    if ((l3[l3_index] & DESC_VALID) != 0)
        return -2;
    l3[l3_index] = user_page_descriptor(physical_address, flags);
    clean_range_to_poc(&l3[l3_index], sizeof(l3[l3_index]));
    invalidate_user_page(virtual_address, asid);
    return 0;
}

int arm64_mmu_unmap_user_l3_page(arm64_mmu_u64 l3_address,
                                 arm64_mmu_u64 virtual_address,
                                 unsigned int asid,
                                 arm64_mmu_u64 *physical_address)
{
    uint64_t *l3;
    uint64_t descriptor;
    uint64_t l3_index;

    if (!table_address_valid(l3_address) ||
        (virtual_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) || asid == 0 ||
        asid > TTBR_ASID_MAX || !physical_address)
        return -1;

    l3 = (uint64_t *)arm64_mmu_kernel_address(l3_address);
    l3_index = (virtual_address >> 12) & 0x1ffu;
    descriptor = l3[l3_index];
    if ((descriptor & (DESC_VALID | DESC_TABLE_PAGE)) !=
        (DESC_VALID | DESC_TABLE_PAGE))
        return -2;

    *physical_address = descriptor & ARM64_TABLE_MASK;
    l3[l3_index] = 0;
    clean_range_to_poc(&l3[l3_index], sizeof(l3[l3_index]));

    invalidate_user_page(virtual_address, asid);
    return 0;
}

int arm64_mmu_remove_user_l3(arm64_mmu_u64 l2_address,
                             arm64_mmu_u64 l3_address,
                             arm64_mmu_u64 virtual_address,
                             unsigned int asid)
{
    uint64_t l2_index;

    if (!table_address_valid(l2_address) ||
        !table_address_valid(l3_address) || l2_address == l3_address ||
        (virtual_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) || asid == 0 ||
        asid > TTBR_ASID_MAX)
        return -1;

    l2_index = (virtual_address >> 21) & 0x1ffu;
    return remove_user_table(l2_address, l3_address, l2_index,
                             virtual_address, asid);
}

int arm64_mmu_remove_user_l2(arm64_mmu_u64 l1_address,
                             arm64_mmu_u64 l2_address,
                             arm64_mmu_u64 virtual_address,
                             unsigned int asid)
{
    uint64_t l1_index;

    if (!table_address_valid(l1_address) ||
        !table_address_valid(l2_address) || l1_address == l2_address ||
        (virtual_address & 0xfffu) != 0 ||
        virtual_address >= (1ULL << 39) || asid == 0 ||
        asid > TTBR_ASID_MAX)
        return -1;

    l1_index = (virtual_address >> 30) & 0x1ffu;
    return remove_user_table(l1_address, l2_address, l1_index,
                             virtual_address, asid);
}

static int switch_user_ttbr0(arm64_mmu_u64 table_address,
                             unsigned int asid,
                             int invalidate)
{
    uint64_t operand;
    uint64_t ttbr;

    if (!table_address_valid(table_address) || asid == 0 ||
        asid > TTBR_ASID_MAX)
        return -1;
    if ((arm64_mmu_read_sctlr() & SCTLR_M) == 0)
        return -2;

    operand = (uint64_t)asid << TTBR_ASID_SHIFT;
    ttbr = operand | table_address;
    __asm__ volatile("dsb ishst" ::: "memory");
    if (invalidate) {
        __asm__ volatile("tlbi aside1, %0" :: "r"(operand));
        __asm__ volatile("dsb ish" ::: "memory");
    }
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(ttbr) : "memory");
    arm64_isb();
    return 0;
}

int arm64_mmu_switch_user_ttbr0(arm64_mmu_u64 table_address,
                                unsigned int asid)
{
    return switch_user_ttbr0(table_address, asid, 1);
}

int arm64_mmu_switch_user_ttbr0_preserve(arm64_mmu_u64 table_address,
                                         unsigned int asid)
{
    return switch_user_ttbr0(table_address, asid, 0);
}

void arm64_mmu_sync_code(arm64_mmu_u64 address,
                         arm64_mmu_u64 length)
{
    uint64_t ctr;
    uint64_t dline_size;
    uint64_t iline_size;
    uint64_t cursor;
    uint64_t end = address + length;

    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    dline_size = 4ULL << ((ctr >> 16) & 0xfu);
    iline_size = 4ULL << (ctr & 0xfu);

    cursor = address & ~(dline_size - 1u);
    while (cursor < end) {
        __asm__ volatile("dc cvau, %0" :: "r"(cursor) : "memory");
        cursor += dline_size;
    }
    __asm__ volatile("dsb ish" ::: "memory");

    cursor = address & ~(iline_size - 1u);
    while (cursor < end) {
        __asm__ volatile("ic ivau, %0" :: "r"(cursor) : "memory");
        cursor += iline_size;
    }
    __asm__ volatile("dsb ish" ::: "memory");
    arm64_isb();
}

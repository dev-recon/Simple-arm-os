/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal ARMv8-A 4 KiB long-descriptor identity map for QEMU virt.
 */

#include <asm/mmu.h>

typedef unsigned long long uint64_t;

#define ARM64_L1_ENTRIES 512u
#define ARM64_L1_BLOCK_SIZE (1ULL << 30)

#define DESC_VALID       (1ULL << 0)
#define DESC_ATTR_INDEX(n) ((uint64_t)(n) << 2)
#define DESC_AF          (1ULL << 10)
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
#define TCR_IPS_SHIFT    32u

#define SCTLR_M          (1ULL << 0)
#define SCTLR_C          (1ULL << 2)
#define SCTLR_SA         (1ULL << 3)
#define SCTLR_SA0        (1ULL << 4)
#define SCTLR_I          (1ULL << 12)

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

arm64_mmu_u64 arm64_mmu_translate_read(arm64_mmu_u64 address)
{
    uint64_t result;

    __asm__ volatile("at s1e1r, %0" :: "r"(address));
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

    for (unsigned int i = 0; i < ARM64_L1_ENTRIES; i++)
        arm64_l1_table[i] = 0;

    /* 0x00000000-0x3fffffff: QEMU virt MMIO, never executable. */
    arm64_l1_table[0] =
        DESC_VALID |
        DESC_ATTR_INDEX(0) |
        DESC_AF |
        DESC_SH_OUTER |
        DESC_PXN |
        DESC_UXN;

    /* 0x40000000-0x7fffffff: QEMU RAM containing kernel, stack and DTB. */
    arm64_l1_table[1] =
        ARM64_L1_BLOCK_SIZE |
        DESC_VALID |
        DESC_ATTR_INDEX(1) |
        DESC_AF |
        DESC_SH_INNER;

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

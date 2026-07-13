/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_MMU_H
#define ARMOS_ARM64_MMU_H

typedef unsigned long long arm64_mmu_u64;

#define ARM64_KERNEL_VA_BASE 0xFFFFFF8000000000ULL
#define ARM64_USER_PAGE_READ  (1u << 0)
#define ARM64_USER_PAGE_WRITE (1u << 1)
#define ARM64_USER_PAGE_EXEC  (1u << 2)

int arm64_mmu_enable_identity_map(void);
int arm64_mmu_prepare_identity_tables(arm64_mmu_u64 l1_address,
                                      arm64_mmu_u64 l2_address,
                                      arm64_mmu_u64 l3_address);
int arm64_mmu_switch_ttbr0(arm64_mmu_u64 table_address);
int arm64_mmu_update_identity_page(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 address,
                                   int present);
int arm64_mmu_protect_kernel_image(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 text_start,
                                   arm64_mmu_u64 text_end,
                                   arm64_mmu_u64 rodata_start,
                                   arm64_mmu_u64 rodata_end);
int arm64_mmu_install_ttbr1(arm64_mmu_u64 l1_address,
                            arm64_mmu_u64 shared_l2_address);
int arm64_mmu_retire_low_map(arm64_mmu_u64 ttbr0_l1_address);
int arm64_mmu_prepare_empty_ttbr0(arm64_mmu_u64 l1_address);
int arm64_mmu_prepare_user_page(arm64_mmu_u64 l1_address,
                                arm64_mmu_u64 l2_address,
                                arm64_mmu_u64 l3_address,
                                arm64_mmu_u64 virtual_address,
                                arm64_mmu_u64 physical_address,
                                unsigned int flags);
int arm64_mmu_prepare_user_l3_page(arm64_mmu_u64 l3_address,
                                   arm64_mmu_u64 virtual_address,
                                   arm64_mmu_u64 physical_address,
                                   unsigned int flags);
int arm64_mmu_switch_user_ttbr0(arm64_mmu_u64 table_address,
                                unsigned int asid);
void arm64_mmu_sync_code(arm64_mmu_u64 address,
                         arm64_mmu_u64 length);
arm64_mmu_u64 arm64_mmu_kernel_address(arm64_mmu_u64 physical_address);
arm64_mmu_u64 arm64_mmu_read_sctlr(void);
arm64_mmu_u64 arm64_mmu_read_tcr(void);
arm64_mmu_u64 arm64_mmu_read_ttbr0(void);
arm64_mmu_u64 arm64_mmu_read_ttbr1(void);
arm64_mmu_u64 arm64_mmu_translate_read(arm64_mmu_u64 address);
arm64_mmu_u64 arm64_mmu_translate_write(arm64_mmu_u64 address);
arm64_mmu_u64 arm64_mmu_translate_user_read(arm64_mmu_u64 address);
arm64_mmu_u64 arm64_mmu_translate_user_write(arm64_mmu_u64 address);

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_MMU_H
#define ARMOS_ARM64_MMU_H

typedef unsigned long long arm64_mmu_u64;

int arm64_mmu_enable_identity_map(void);
arm64_mmu_u64 arm64_mmu_read_sctlr(void);
arm64_mmu_u64 arm64_mmu_read_tcr(void);
arm64_mmu_u64 arm64_mmu_read_ttbr0(void);
arm64_mmu_u64 arm64_mmu_translate_read(arm64_mmu_u64 address);

#endif

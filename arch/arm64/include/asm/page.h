/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ASM_ARM64_PAGE_H
#define ASM_ARM64_PAGE_H

#define ARCH_PAGE_SIZE        4096ULL
#define ARCH_PAGE_SHIFT       12u
#define ARCH_PAGE_OFFSET_MASK 0x0000000000000FFFULL
#define ARCH_PAGE_MASK        0xFFFFFFFFFFFFF000ULL

#if ARCH_PAGE_SIZE != 4096ULL
#error "ARM64 currently requires 4KB pages"
#endif

#endif /* ASM_ARM64_PAGE_H */

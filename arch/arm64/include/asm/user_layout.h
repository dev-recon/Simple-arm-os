/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/user_layout.h
 * Layer: ARM64 / user virtual layout
 *
 * Responsibilities:
 * - Define the lower 39-bit AArch64 user virtual-address layout.
 * - Keep generic heap, mmap, shared-memory, stack, and signal regions apart.
 *
 * Notes:
 * - TTBR0_EL1 currently uses T0SZ=25, giving user space 512 GiB.
 * - The low 64 KiB remains unmapped so null and near-null faults stay visible.
 */

#ifndef ASM_ARM64_USER_LAYOUT_H
#define ASM_ARM64_USER_LAYOUT_H

#define ARCH_USER_SPACE_START          0x0000000000010000ULL
#define ARCH_USER_HEAP_START           0x0000000008000000ULL
#define ARCH_USER_SHM_START            0x0000004000000000ULL
#define ARCH_USER_SHM_END              0x0000004400000000ULL
#define ARCH_USER_STACK_TOP            0x0000007F00000000ULL
#define ARCH_USER_STACK_SIZE           (8ULL * 1024ULL * 1024ULL)
#define ARCH_USER_STACK_BOTTOM         \
    (ARCH_USER_STACK_TOP - ARCH_USER_STACK_SIZE)
#define ARCH_USER_HEAP_END             ARCH_USER_SHM_START
#define ARCH_USER_SPACE_END            ARCH_USER_STACK_TOP

#define ARCH_USER_SIGNAL_REGION_START  ARCH_USER_STACK_TOP
#define ARCH_USER_SIGNAL_REGION_END    0x0000007FFFF00000ULL
#define ARCH_USER_SIGNAL_REGION_SIZE   \
    (ARCH_USER_SIGNAL_REGION_END - ARCH_USER_SIGNAL_REGION_START)

#endif /* ASM_ARM64_USER_LAYOUT_H */

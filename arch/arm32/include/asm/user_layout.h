/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/user_layout.h
 * Layer: ARM32 / user virtual layout
 *
 * Responsibilities:
 * - Define the ARM32 user-space virtual address layout.
 * - Keep the split-TTBR boundary assumptions out of generic kernel headers.
 *
 * Current layout:
 *   0x00000000 - 0x00010000 : reserved low page/trap area
 *   0x00010000 - 0x08000000 : user text/data load area
 *   0x08000000 - 0x30000000 : user heap
 *   0x30000000 - 0x34000000 : shared-memory mappings
 *   0x34000000 - 0x37000000 : anonymous mmap area
 *   0x37000000 - 0x3F000000 : user stack
 *   0x3F000000 - 0x3FFFF000 : signal stacks
 */

#ifndef ASM_ARM32_USER_LAYOUT_H
#define ASM_ARM32_USER_LAYOUT_H

#define ARCH_USER_SPACE_START          0x00010000u
#define ARCH_USER_HEAP_START           0x08000000u
#define ARCH_USER_SHM_START            0x30000000u
#define ARCH_USER_SHM_END              0x34000000u
#define ARCH_USER_STACK_TOP            0x3F000000u
#define ARCH_USER_STACK_SIZE           (8u * 1024u * 1024u)
#define ARCH_USER_STACK_BOTTOM         (ARCH_USER_STACK_TOP - ARCH_USER_STACK_SIZE)
#define ARCH_USER_HEAP_END             ARCH_USER_SHM_START
#define ARCH_USER_SPACE_END            ARCH_USER_STACK_TOP

#define ARCH_USER_SIGNAL_REGION_START  ARCH_USER_STACK_TOP
#define ARCH_USER_SIGNAL_REGION_END    0x3FFFF000u
#define ARCH_USER_SIGNAL_REGION_SIZE   \
    (ARCH_USER_SIGNAL_REGION_END - ARCH_USER_SIGNAL_REGION_START)

#endif /* ASM_ARM32_USER_LAYOUT_H */

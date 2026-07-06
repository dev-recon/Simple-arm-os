/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/page.h
 * Layer: ARM32 / paging constants
 *
 * Responsibilities:
 * - Define the architectural page size and masks used by the generic kernel.
 * - Keep ARM short-descriptor page assumptions out of portable headers.
 */

#ifndef ASM_ARM32_PAGE_H
#define ASM_ARM32_PAGE_H

#define ARCH_PAGE_SIZE        4096u
#define ARCH_PAGE_SHIFT       12u
#define ARCH_PAGE_OFFSET_MASK 0x00000FFFu
#define ARCH_PAGE_MASK        0xFFFFF000u

#if ARCH_PAGE_SIZE != 4096u
#error "ARM32 currently requires 4KB pages"
#endif

#endif /* ASM_ARM32_PAGE_H */

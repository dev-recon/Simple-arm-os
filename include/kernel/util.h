/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/util.h
 * Layer: Kernel / generic utility macros
 *
 * Responsibilities:
 * - Provide small freestanding helpers shared by kernel subsystems.
 * - Keep generic alignment, page, and array helpers out of kernel.h.
 */

#ifndef KERNEL_UTIL_H
#define KERNEL_UTIL_H

#include <kernel/types.h>

#define ALIGN_UP(x, align)      (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align)    ((x) & ~((align) - 1))

#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & (PAGE_SIZE - 1)) == 0)

#define ADDR_TO_PAGE(addr)      ((addr) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(page)      ((page) << PAGE_SHIFT)

#define MIN(a, b)               ((a) < (b) ? (a) : (b))
#define MAX(a, b)               ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))

#endif /* KERNEL_UTIL_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-CPU page allocator for architecture bring-up before the full physical
 * memory manager and its synchronization primitives are available.
 */

#ifndef _KERNEL_EARLY_PAGE_ALLOCATOR_H
#define _KERNEL_EARLY_PAGE_ALLOCATOR_H

#include <kernel/types.h>

typedef struct {
    paddr_t base;
    paddr_t end;
    uint32_t total_pages;
    uint32_t free_pages;
    uint8_t *bitmap;
    uint32_t bitmap_bytes;
} early_page_allocator_t;

int early_page_allocator_init(early_page_allocator_t *allocator,
                              paddr_t start,
                              paddr_t end,
                              uint8_t *bitmap,
                              uint32_t bitmap_bytes);
int early_page_alloc_pages(early_page_allocator_t *allocator,
                           uint32_t count,
                           paddr_t *address);
int early_page_free_pages(early_page_allocator_t *allocator,
                          paddr_t address,
                          uint32_t count);
int early_page_reserve(early_page_allocator_t *allocator,
                       paddr_t start,
                       paddr_t end);

#endif /* _KERNEL_EARLY_PAGE_ALLOCATOR_H */

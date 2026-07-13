/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/early_page_allocator.h
 * Layer: Kernel / early physical memory interface
 *
 * Responsibilities:
 * - Define the bitmap-backed early physical page allocator state.
 * - Expose contiguous allocation, release and range reservation operations.
 *
 * Notes:
 * - The interface is single-CPU and is retired once the full synchronized
 *   physical memory manager becomes available.
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

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/memory/early_page_allocator.c
 * Layer: Kernel / early physical memory
 *
 * Responsibilities:
 * - Allocate and release contiguous physical pages during early boot.
 * - Reserve firmware, kernel and bootstrap ranges in a compact bitmap.
 *
 * Notes:
 * - This allocator is intentionally single-CPU and precedes the synchronized
 *   physical memory manager.
 */

#include <kernel/early_page_allocator.h>

static bool page_is_used(const early_page_allocator_t *allocator,
                         uint32_t page)
{
    return (allocator->bitmap[page >> 3] & (uint8_t)(1u << (page & 7u))) != 0;
}

static void set_page_used(early_page_allocator_t *allocator, uint32_t page)
{
    allocator->bitmap[page >> 3] |= (uint8_t)(1u << (page & 7u));
}

static void set_page_free(early_page_allocator_t *allocator, uint32_t page)
{
    allocator->bitmap[page >> 3] &= (uint8_t)~(1u << (page & 7u));
}

int early_page_allocator_init(early_page_allocator_t *allocator,
                              paddr_t start,
                              paddr_t end,
                              uint8_t *bitmap,
                              uint32_t bitmap_bytes)
{
    paddr_t aligned_start;
    paddr_t aligned_end;
    paddr_t span;
    uint32_t pages;
    uint32_t required_bytes;
    uint32_t i;

    if (!allocator || !bitmap)
        return -EINVAL;

    aligned_start = (start + PAGE_OFFSET_MASK) & PAGE_MASK;
    aligned_end = end & PAGE_MASK;
    if (aligned_end <= aligned_start)
        return -EINVAL;

    span = aligned_end - aligned_start;
    pages = (uint32_t)(span >> PAGE_SHIFT);
    required_bytes = (pages + 7u) >> 3;
    if (pages == 0 || bitmap_bytes < required_bytes)
        return -ENOMEM;

    for (i = 0; i < required_bytes; i++)
        bitmap[i] = 0;

    allocator->base = aligned_start;
    allocator->end = aligned_end;
    allocator->total_pages = pages;
    allocator->free_pages = pages;
    allocator->bitmap = bitmap;
    allocator->bitmap_bytes = required_bytes;
    return 0;
}

int early_page_alloc_pages(early_page_allocator_t *allocator,
                           uint32_t count,
                           paddr_t *address)
{
    uint32_t first;
    uint32_t run;
    uint32_t page;
    uint32_t i;

    if (!allocator || !address || count == 0)
        return -EINVAL;
    if (count > allocator->free_pages)
        return -ENOMEM;

    first = 0;
    run = 0;
    for (page = 0; page < allocator->total_pages; page++) {
        if (page_is_used(allocator, page)) {
            run = 0;
            continue;
        }

        if (run == 0)
            first = page;
        run++;
        if (run != count)
            continue;

        for (i = 0; i < count; i++)
            set_page_used(allocator, first + i);
        allocator->free_pages -= count;
        *address = allocator->base + ((paddr_t)first << PAGE_SHIFT);
        return 0;
    }

    return -ENOMEM;
}

int early_page_free_pages(early_page_allocator_t *allocator,
                          paddr_t address,
                          uint32_t count)
{
    uint32_t first;
    uint32_t i;

    if (!allocator || count == 0 || (address & PAGE_OFFSET_MASK) != 0)
        return -EINVAL;
    if (address < allocator->base || address >= allocator->end)
        return -EINVAL;

    first = (uint32_t)((address - allocator->base) >> PAGE_SHIFT);
    if (first > allocator->total_pages ||
        count > allocator->total_pages - first)
        return -EINVAL;

    for (i = 0; i < count; i++) {
        if (!page_is_used(allocator, first + i))
            return -EINVAL;
    }

    for (i = 0; i < count; i++)
        set_page_free(allocator, first + i);
    allocator->free_pages += count;
    return 0;
}

int early_page_reserve(early_page_allocator_t *allocator,
                       paddr_t start,
                       paddr_t end)
{
    paddr_t clipped_start;
    paddr_t clipped_end;
    uint32_t first;
    uint32_t last;
    uint32_t page;

    if (!allocator || end <= start)
        return -EINVAL;
    if (end <= allocator->base || start >= allocator->end)
        return 0;

    clipped_start = start < allocator->base ? allocator->base : start;
    clipped_end = end > allocator->end ? allocator->end : end;
    clipped_start &= PAGE_MASK;
    clipped_end = (clipped_end + PAGE_OFFSET_MASK) & PAGE_MASK;
    if (clipped_end > allocator->end)
        clipped_end = allocator->end;

    first = (uint32_t)((clipped_start - allocator->base) >> PAGE_SHIFT);
    last = (uint32_t)((clipped_end - allocator->base) >> PAGE_SHIFT);
    for (page = first; page < last; page++) {
        if (!page_is_used(allocator, page)) {
            set_page_used(allocator, page);
            allocator->free_pages--;
        }
    }
    return 0;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/address_space.h
 * Layer: Kernel / architecture compatibility
 *
 * Responsibilities:
 * - Expose kernel virtual/physical layout helpers through generic names.
 * - Keep generic code away from architecture memory-layout constants unless it
 *   explicitly needs address-space semantics.
 *
 * Notes:
 * - The active architecture backend owns the concrete KERNEL_* and VIRT_*
 *   constants through asm/memory_layout.h.
 */

#ifndef _KERNEL_ADDRESS_SPACE_H
#define _KERNEL_ADDRESS_SPACE_H

#include <kernel/types.h>
#include <kernel/linker.h>
#include <kernel/arch_memory_layout.h>

uint32_t get_kernel_memory_size(void);

#define VIRT_RAM_SIZE           get_kernel_memory_size()
#define VIRT_RAM_END            (VIRT_RAM_START + VIRT_RAM_SIZE)

static inline bool phys_in_direct_map(paddr_t paddr)
{
    return paddr >= VIRT_RAM_START &&
           paddr < (VIRT_RAM_START + KERNEL_DIRECT_MAP_SIZE);
}

static inline bool virt_in_direct_map(vaddr_t vaddr)
{
    return vaddr >= KERNEL_DIRECT_MAP_BASE && vaddr < KERNEL_DIRECT_MAP_END;
}

static inline vaddr_t phys_to_virt(paddr_t paddr)
{
    return paddr + KERNEL_DIRECT_MAP_OFFSET;
}

static inline paddr_t virt_to_phys(vaddr_t vaddr)
{
    if (virt_in_direct_map(vaddr))
        return vaddr - KERNEL_DIRECT_MAP_OFFSET;

    /*
     * Compatibility for the boot identity window and current low kernel link
     * address. Drivers and new allocator users should not rely on this path.
     */
    return vaddr;
}

#define IS_DEVICE_ADDR(addr)    ((addr) >= DEVICE_START && (addr) < DEVICE_END)
#define IS_VALID_RAM(addr)      ((addr) >= VIRT_RAM_START && (addr) < VIRT_RAM_END)
#define IS_VIRTIO_ADDR(addr)    ((addr) >= VIRT_VIRTIO_BASE && (addr) < (VIRT_VIRTIO_BASE + VIRT_VIRTIO_SIZE * 8))
#define IS_GIC_ADDR(addr)       ((addr) >= VIRT_GIC_DIST_BASE && (addr) < (VIRT_GIC_VCPU_BASE + VIRT_GIC_VCPU_SIZE))

static inline vaddr_t get_kernel_start(void) { return KERNEL_START; }
static inline vaddr_t get_kernel_end(void) { return KERNEL_END; }
static inline size_t get_kernel_size(void) { return KERNEL_SIZE; }

static inline vaddr_t get_text_start(void) { return KERNEL_TEXT_START; }
static inline vaddr_t get_text_end(void) { return KERNEL_TEXT_END; }
static inline size_t get_text_size(void)
{
    return (size_t)(KERNEL_TEXT_END - KERNEL_TEXT_START);
}

static inline vaddr_t get_data_start(void) { return KERNEL_DATA_START; }
static inline vaddr_t get_data_end(void) { return KERNEL_DATA_END; }
static inline size_t get_data_size(void)
{
    return (size_t)(KERNEL_DATA_END - KERNEL_DATA_START);
}

static inline vaddr_t get_bss_start(void) { return KERNEL_BSS_START; }
static inline vaddr_t get_bss_end(void) { return KERNEL_BSS_END; }
static inline size_t get_bss_size(void)
{
    return (size_t)(KERNEL_BSS_END - KERNEL_BSS_START);
}

static inline vaddr_t get_heap_start(void) { return KERNEL_HEAP_START; }

void print_kernel_layout(void);

#endif /* _KERNEL_ADDRESS_SPACE_H */

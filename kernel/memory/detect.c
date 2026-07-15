/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/memory/detect.c
 * Layer: Kernel / physical memory discovery
 *
 * Responsibilities:
 * - Discover the platform RAM span from the boot device tree.
 * - Clamp usable RAM before the first platform device window.
 * - Provide one architecture-neutral memory-size contract to the allocator.
 *
 * Notes:
 * - Platforms without a valid DTB use their conservative declared fallback.
 * - Destructive RAM probing is intentionally excluded from common boot.
 */

#include <kernel/arch_platform.h>
#include <kernel/fdt.h>
#include <kernel/memory.h>

uint32_t kernel_memory_size;

static uint32_t platform_ram_limit(void)
{
    uint64_t ram_start = (uint64_t)arch_platform_ram_start();
    uint64_t device_start = (uint64_t)arch_platform_device_start();

    if (device_start > ram_start) {
        uint64_t limit = device_start - ram_start;

        if (limit <= 0xffffffffULL)
            return (uint32_t)limit;
    }
    return 0xffffffffu;
}

uint32_t detect_memory(void)
{
    fdt_memory_layout_t layout;
    paddr_t ram_start = arch_platform_ram_start();
    uint64_t detected = 0;
    uint32_t limit = platform_ram_limit();
    uint32_t index;

    if (kernel_memory_size != 0)
        return kernel_memory_size;

    if (dtb_address != 0 &&
        fdt_read_memory_layout((void *)(uintptr_t)dtb_address, &layout)) {
        for (index = 0; index < layout.memory_count; index++) {
            uint64_t start = layout.memory[index].start;
            uint64_t size = layout.memory[index].size;
            uint64_t end = start + size;

            if (start <= ram_start && end > ram_start) {
                detected = end - ram_start;
                break;
            }
        }
    }

    if (detected == 0)
        detected = arch_platform_ram_fallback_size();
    if (detected > limit)
        detected = limit;
    if (detected > 0xffffffffULL)
        detected = 0xffffffffULL;

    kernel_memory_size = (uint32_t)detected;
    return kernel_memory_size;
}

uint32_t get_kernel_memory_size(void)
{
    return detect_memory();
}

void init_memory_detection(void)
{
}

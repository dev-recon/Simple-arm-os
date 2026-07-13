/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/process/exec.c
 * Layer: ARM64 / executable ABI
 *
 * Responsibilities:
 * - Parse AArch64 ELF64 images into the common executable layout.
 * - Synchronize loaded user code with the AArch64 instruction cache.
 *
 * Notes:
 * - VFS reads, VM mappings and process publication remain common code.
 */

#include <asm/mmu.h>
#include <kernel/arch_exec.h>
#include <kernel/elf64.h>
#include <kernel/memory.h>
#include <kernel/string.h>

int arch_exec_parse_image(const void *image, size_t image_size,
                          exec_image_layout_t *layout)
{
    const uint8_t *bytes = image;
    const elf64_header_t *header = image;
    uint32_t index;

    if (!layout ||
        elf64_validate_aarch64(image, image_size, USER_SPACE_END) != 0)
        return -1;

    memset(layout, 0, sizeof(*layout));
    layout->entry = (vaddr_t)header->entry;
    for (index = 0; index < header->phnum; index++) {
        const elf64_program_header_t *program =
            (const elf64_program_header_t *)(const void *)(
                bytes + header->phoff + index * sizeof(*program));
        exec_image_segment_t *segment;

        if (program->type != ELF64_PT_LOAD)
            continue;
        if (layout->segment_count >= EXEC_IMAGE_MAX_SEGMENTS)
            return -1;
        segment = &layout->segments[layout->segment_count++];
        segment->file_offset = program->offset;
        segment->file_size = program->filesz;
        segment->memory_size = program->memsz;
        segment->virtual_address = (vaddr_t)program->vaddr;
        if (program->flags & ELF64_PF_R)
            segment->flags |= VMA_READ;
        if (program->flags & ELF64_PF_W)
            segment->flags |= VMA_WRITE;
        if (program->flags & ELF64_PF_X)
            segment->flags |= VMA_EXEC;
    }
    return layout->segment_count ? 0 : -1;
}

void arch_sync_loaded_user_page(vaddr_t mapped_vaddr, size_t size,
                                bool executable)
{
    if (executable)
        arm64_mmu_sync_code(mapped_vaddr, size);
}

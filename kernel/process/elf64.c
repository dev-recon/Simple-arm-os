/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/process/elf64.c
 * Layer: Kernel / ELF64 image loading
 *
 * Responsibilities:
 * - Validate ELF64/AArch64 executable headers and load-segment bounds.
 * - Translate ELF permissions to generic VMA flags.
 * - Populate mapped segments through architecture-neutral callbacks.
 *
 * Notes:
 * - Dynamic linking, relocations and interpreters are intentionally rejected.
 */

#include <kernel/elf64.h>
#include <kernel/memory.h>

static int add_overflows_u64(uint64_t left, uint64_t right)
{
    return left + right < left;
}

static const elf64_program_header_t *program_header(
    const uint8_t *image, const elf64_header_t *header, unsigned int index)
{
    return (const elf64_program_header_t *)(const void *)(
        image + header->phoff + (uint64_t)index * header->phentsize);
}

int elf64_validate_aarch64(const void *image, size_t image_size,
                           vaddr_t user_limit)
{
    const uint8_t *bytes = (const uint8_t *)image;
    const elf64_header_t *header = (const elf64_header_t *)image;
    unsigned int index;
    int loadable = 0;
    int executable_entry = 0;

    if (!image || image_size < sizeof(*header) || user_limit == 0)
        return -1;
    if (bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' ||
        bytes[3] != 'F' || bytes[4] != 2 || bytes[5] != 1 ||
        bytes[6] != 1 || header->type != ELF64_ET_EXEC ||
        header->machine != ELF64_EM_AARCH64 || header->version != 1 ||
        header->ehsize != sizeof(*header) ||
        header->phentsize != sizeof(elf64_program_header_t) ||
        header->phnum == 0 || header->phoff < sizeof(*header) ||
        header->entry >= user_limit)
        return -2;
    if (add_overflows_u64(header->phoff,
                          (uint64_t)header->phnum * header->phentsize) ||
        header->phoff + (uint64_t)header->phnum * header->phentsize >
            image_size)
        return -3;

    for (index = 0; index < header->phnum; index++) {
        const elf64_program_header_t *segment =
            program_header(bytes, header, index);

        if (segment->type == ELF64_PT_DYNAMIC ||
            segment->type == ELF64_PT_INTERP)
            return -4;
        if (segment->type != ELF64_PT_LOAD)
            continue;
        loadable = 1;
        if (segment->memsz < segment->filesz || segment->memsz == 0 ||
            add_overflows_u64(segment->offset, segment->filesz) ||
            segment->offset + segment->filesz > image_size ||
            add_overflows_u64(segment->vaddr, segment->memsz) ||
            segment->vaddr < USER_SPACE_START ||
            segment->vaddr + segment->memsz > user_limit ||
            (segment->align > 1 &&
             ((segment->align & (segment->align - 1)) != 0 ||
              (segment->vaddr & (segment->align - 1)) !=
                  (segment->offset & (segment->align - 1)))) ||
            (segment->flags & ~(ELF64_PF_R | ELF64_PF_W | ELF64_PF_X)) != 0 ||
            (segment->flags & ELF64_PF_R) == 0 ||
            (segment->flags & (ELF64_PF_W | ELF64_PF_X)) ==
                (ELF64_PF_W | ELF64_PF_X))
            return -5;
        if ((segment->flags & ELF64_PF_X) != 0 &&
            header->entry >= segment->vaddr &&
            header->entry < segment->vaddr + segment->memsz)
            executable_entry = 1;
    }
    return loadable && executable_entry ? 0 : -6;
}

int elf64_load_aarch64(const void *image, size_t image_size,
                       vaddr_t user_limit, const elf64_loader_ops_t *ops,
                       void *context, vaddr_t *entry)
{
    const uint8_t *bytes = (const uint8_t *)image;
    const elf64_header_t *header = (const elf64_header_t *)image;
    unsigned int index;

    if (!ops || !ops->map || !ops->copy || !ops->zero || !entry ||
        elf64_validate_aarch64(image, image_size, user_limit) != 0)
        return -1;

    for (index = 0; index < header->phnum; index++) {
        const elf64_program_header_t *segment =
            program_header(bytes, header, index);
        vaddr_t start;
        vaddr_t end;
        unsigned int flags = 0;

        if (segment->type != ELF64_PT_LOAD)
            continue;
        start = (vaddr_t)segment->vaddr & PAGE_MASK;
        end = ((vaddr_t)(segment->vaddr + segment->memsz) +
               PAGE_SIZE - 1) & PAGE_MASK;
        if (segment->flags & ELF64_PF_R)
            flags |= VMA_READ;
        if (segment->flags & ELF64_PF_W)
            flags |= VMA_WRITE;
        if (segment->flags & ELF64_PF_X)
            flags |= VMA_EXEC;
        if (ops->map(context, start, end - start, flags) != 0 ||
            ops->copy(context, (vaddr_t)segment->vaddr,
                      bytes + segment->offset,
                      (size_t)segment->filesz) != 0 ||
            (segment->memsz > segment->filesz &&
             ops->zero(context,
                       (vaddr_t)(segment->vaddr + segment->filesz),
                       (size_t)(segment->memsz - segment->filesz)) != 0))
            return -2;
    }
    *entry = (vaddr_t)header->entry;
    return 0;
}

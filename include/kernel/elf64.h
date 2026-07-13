/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/elf64.h
 * Layer: Kernel / ELF64 image loading
 *
 * Responsibilities:
 * - Define the ELF64 file and program-header ABI used by AArch64 exec.
 * - Validate loadable AArch64 executable images with overflow checks.
 * - Load segments through VM callbacks independent of VFS acquisition.
 *
 * Notes:
 * - Point 5 will provide file-backed image bytes through VFS.
 */

#ifndef _KERNEL_ELF64_H
#define _KERNEL_ELF64_H

#include <kernel/types.h>

#define ELF64_IDENT_SIZE 16u
#define ELF64_PT_LOAD    1u
#define ELF64_PT_DYNAMIC 2u
#define ELF64_PT_INTERP  3u
#define ELF64_PF_X       1u
#define ELF64_PF_W       2u
#define ELF64_PF_R       4u
#define ELF64_ET_EXEC    2u
#define ELF64_EM_AARCH64 183u

typedef struct elf64_header {
    uint8_t ident[ELF64_IDENT_SIZE];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf64_header_t;

typedef struct elf64_program_header {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf64_program_header_t;

typedef struct elf64_loader_ops {
    int (*map)(void *context, vaddr_t start, size_t length,
               unsigned int flags);
    int (*copy)(void *context, vaddr_t destination,
                const void *source, size_t length);
    int (*zero)(void *context, vaddr_t destination, size_t length);
} elf64_loader_ops_t;

int elf64_validate_aarch64(const void *image, size_t image_size,
                           vaddr_t user_limit);
int elf64_load_aarch64(const void *image, size_t image_size,
                       vaddr_t user_limit, const elf64_loader_ops_t *ops,
                       void *context, vaddr_t *entry);

#endif /* _KERNEL_ELF64_H */

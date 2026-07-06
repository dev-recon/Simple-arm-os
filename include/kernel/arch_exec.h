/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_exec.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Declare architecture checks and cache maintenance needed by exec().
 * - Keep the ELF loader policy independent from ARM-specific machine IDs.
 *
 * Notes:
 * - The generic loader still owns ELF layout validation and VMA creation.
 */

#ifndef _KERNEL_ARCH_EXEC_H
#define _KERNEL_ARCH_EXEC_H

#include <kernel/elf32.h>
#include <kernel/types.h>

bool arch_validate_elf_header(const elf32_ehdr_t* header);
/*
 * The page has just been filled through a kernel temporary mapping.  The arch
 * hook owns the cache maintenance needed before the same physical page is
 * installed in the user address space.
 */
void arch_sync_loaded_user_page(vaddr_t mapped_vaddr, size_t size, bool executable);

#endif /* _KERNEL_ARCH_EXEC_H */

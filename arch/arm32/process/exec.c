/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/process/exec.c
 * Layer: ARM32 / exec ABI support
 *
 * Responsibilities:
 * - Validate ARM ELF32 machine type for exec().
 * - Perform ARMv7 cache maintenance after loading user text/data pages.
 *
 * Notes:
 * - AArch64 will provide the same tiny hooks with different machine IDs and
 *   cache maintenance rules.
 */

#include <kernel/arch_exec.h>
#include <asm/arm.h>

#define EM_ARM 40u

bool arch_validate_elf_header(const elf32_ehdr_t* header)
{
    return header && header->e_machine == EM_ARM;
}

void arch_sync_loaded_user_page(vaddr_t mapped_vaddr, size_t size, bool executable)
{
    uintptr_t start;
    uintptr_t end;

    start = mapped_vaddr & ~63u;
    end = (mapped_vaddr + size + 63u) & ~63u;

    invalidate_dcache_range((vaddr_t)start, (vaddr_t)end);
    dcache_clean_by_va((void *)mapped_vaddr, size);

    if (executable)
        sync_icache_for_exec();

    clean_dcache_by_mva((void *)mapped_vaddr, size);
}

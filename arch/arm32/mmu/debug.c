/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/mmu/debug.c
 * Layer: ARM32 / MMU diagnostics
 *
 * Responsibilities:
 * - Keep ARM short-descriptor page-table debug helpers out of generic code.
 * - Provide low-level probes used during MMU and exec bring-up.
 *
 * Notes:
 * - These helpers intentionally know about TTBR0, L1/L2 indices, and the
 *   ARMv7-A short-descriptor format.
 */

#include <kernel/memory.h>
#include <kernel/address_space.h>
#include <kernel/kprintf.h>
#include <asm/mmu.h>

void check_instruction(vaddr_t test_vaddr, paddr_t phys_addr, uint32_t instruction)
{
    uint32_t l1_index = get_L1_index(test_vaddr);
    uint32_t l2_index = L2_INDEX(test_vaddr);

    KDEBUG("  Testing user mapping 0x%08X:\n", test_vaddr);
    KDEBUG("    L1 index: %u, L2 index: %u\n", l1_index, l2_index);

    uint32_t current_ttbr0 = get_ttbr0();
    pgdir_cpu_t active_pgdir = (pgdir_cpu_t)phys_to_virt((paddr_t)(current_ttbr0 & ~0x7F));
    uint32_t l1_entry = active_pgdir[l1_index];

    KDEBUG("Current TTBR0 = 0x%08X\n", (uint32_t)active_pgdir);
    if (l1_entry & 0x1) {
        KDEBUG("    User area properly mapped via page table\n");
    } else {
        KERROR("    User area not mapped!\n");
    }

    KDEBUG("=== FINAL INSTRUCTION CHECK ===\n");

    paddr_t paddr = phys_addr;
    uint32_t *phys_code = (uint32_t*)phys_to_virt(paddr);
    uint32_t first_instruction = *phys_code;

    KDEBUG("  First instruction at 0x8000: user code (phys 0x%08X): 0x%08X\n",
           paddr, first_instruction);
    KDEBUG("  Expected: 0x%08X\n", instruction);

    if (first_instruction == instruction) {
        KDEBUG("  Instruction correct, ready for execution\n");
    } else {
        KERROR("  Instruction mismatch!\n");
    }

    uint32_t *user_code = (uint32_t*)test_vaddr;
    KDEBUG("=== USER CODE OK === user code 0x%08X\n", *user_code);
}

void dbg_dump_pte_0x8000(void)
{
    uint32_t *l1 = (uint32_t*)map_temp_page(get_ttbr0() & 0xFFFFC000u);
    uint32_t e1 = l1[0];

    kprintf("DBG L1[0]=0x%08X for TTBR0 = 0x%08X\n", e1, get_ttbr0());

    if ((e1 & 3u) == 1u) {
        uint32_t l2_pa_1kb = e1 & 0xFFFFFC00u;
        paddr_t l2_page_pa = l2_pa_1kb & ~0x3FFu;
        uint32_t l2_off = l2_pa_1kb & 0x3FFu;

        uint8_t *l2p = (uint8_t*)map_temp_page(l2_page_pa);
        volatile uint32_t *l2 = (volatile uint32_t*)(l2p + l2_off);

        kprintf("DBG L2[8]=0x%08X (L2_page_pa=0x%08X)\n", l2[8], l2_page_pa);
        unmap_temp_page((void*)l2p);
    }

    unmap_temp_page((void*)l1);
}

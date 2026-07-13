/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/task/task_context.c
 * Layer: ARM64 / task switching
 *
 * Responsibilities:
 * - Validate the address-space identity carried by a task context.
 * - Resolve generic vm_space_t references through the ARM64 backend.
 * - Activate TTBR0 and its ASID before switching kernel register state.
 *
 * Notes:
 * - A zero TTBR0/ASID pair denotes a bootstrap kernel-only context.
 * - Residency decisions are delegated to the owned user-VM object.
 */

#include <asm/mmu.h>
#include <asm/task_context.h>
#include <asm/user_vm.h>

int arm64_task_context_switch_address_space(
    arm64_task_context_t *previous,
    const arm64_task_context_t *next)
{
    int result;

    if (!previous || !next)
        return -1;

    if (next->vm_space) {
        if (next->ttbr0 !=
                (paddr_t)(uintptr_t)next->vm_space->pgdir ||
            next->asid != next->vm_space->asid)
            return -2;
        result = arm64_user_vm_activate_space(next->vm_space);
        if (result != 0)
            return -3;
    } else if (next->ttbr0 != 0 || next->asid != 0) {
        if (next->ttbr0 == 0 || next->asid == 0)
            return -4;
        result = arm64_mmu_switch_user_ttbr0(next->ttbr0, next->asid);
        if (result != 0)
            return -5;
    }

    arm64_task_context_switch(previous, next);
    return 0;
}

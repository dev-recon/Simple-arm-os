/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/task_context.h
 * Layer: ARM64 / task context ABI
 *
 * Responsibilities:
 * - Group kernel callee-saved state, EL0 state and address-space identity.
 * - Define the bootstrap contract consumed by context_switch.S.
 *
 * Notes:
 * - This is not yet wired to the generic scheduler task_t lifecycle.
 * - SIMD state and per-task kernel stacks will be added with scheduler work.
 */

#ifndef ASM_ARM64_TASK_CONTEXT_H
#define ASM_ARM64_TASK_CONTEXT_H

#include <asm/user_context.h>
#include <kernel/types.h>

#define ARM64_TASK_FLAG_RETURNS_TO_USER (1u << 0)

typedef struct arm64_kernel_context {
    uint64_t x[12];
    uint64_t sp;
    uint64_t pc;
} arm64_kernel_context_t;

typedef struct arm64_task_context {
    arm64_kernel_context_t kernel;
    arm64_user_context_t user;
    paddr_t ttbr0;
    uint32_t asid;
    uint32_t flags;
} __attribute__((aligned(16))) arm64_task_context_t;

_Static_assert(sizeof(arm64_kernel_context_t) == 112,
               "AArch64 kernel context ABI size changed");
_Static_assert(sizeof(arm64_task_context_t) == 400,
               "AArch64 task context ABI size changed");

void arm64_task_context_switch(arm64_task_context_t *previous,
                               const arm64_task_context_t *next);
void arm64_task_context_probe_entry(void) __attribute__((noreturn));

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/user_context.h
 * Layer: ARM64 / userspace context ABI
 *
 * Responsibilities:
 * - Describe the complete AArch64 EL0 general-register image.
 * - Provide one layout for EL0 entry, exception capture and future tasks.
 *
 * Notes:
 * - Field order is an assembly ABI and must remain tied to asm-offsets.c.
 * - Floating-point and SIMD state are intentionally outside this milestone.
 */

#ifndef ASM_ARM64_USER_CONTEXT_H
#define ASM_ARM64_USER_CONTEXT_H

#include <kernel/types.h>

#define ARM64_USER_PSTATE_EL0T_MASKED 0x3c0ULL

typedef struct arm64_user_context {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} __attribute__((aligned(16))) arm64_user_context_t;

_Static_assert(sizeof(arm64_user_context_t) == 272,
               "AArch64 user context ABI size changed");

#endif

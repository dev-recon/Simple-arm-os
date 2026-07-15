/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/exception_frame.h
 * Layer: ARM64 / exception ABI
 *
 * Responsibilities:
 * - Define the EL1 exception frame shared by C and vectors.S.
 * - Embed the reusable EL0 register image as the frame prefix.
 *
 * Notes:
 * - The reserved word keeps the stack frame aligned to 16 bytes.
 * - Layout changes must update generated offsets and pass the size assertion.
 */

#ifndef ASM_ARM64_EXCEPTION_FRAME_H
#define ASM_ARM64_EXCEPTION_FRAME_H

#include <asm/user_context.h>

typedef struct arm64_exception_frame {
    arm64_user_context_t user;
    uint64_t esr;
    uint64_t far;
    uint64_t vector;
    uint64_t reserved;
} arm64_exception_frame_t;

_Static_assert(sizeof(arm64_exception_frame_t) == 304,
               "AArch64 exception frame ABI size changed");

#endif

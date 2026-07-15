/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/user/el0.S
 * Layer: ARM64 / userspace entry
 *
 * Responsibilities:
 * - Restore an arm64_user_context_t and enter EL0t through ERET.
 * - Implement the architecture endpoint used by common task scheduling.
 *
 * Notes:
 * - Program loading and process policy remain in the common kernel.
 */

.include "asm-offsets.h"

.section .text
.align 4
.global arm64_enter_el0
.type arm64_enter_el0, %function
arm64_enter_el0:
    mov x30, x0
    ldr x16, [x30, #ARM64_CTX_SP]
    msr sp_el0, x16
    ldr x16, [x30, #ARM64_CTX_PC]
    msr elr_el1, x16
    ldr x16, [x30, #ARM64_CTX_PSTATE]
    msr spsr_el1, x16
    isb
    ldp x0,  x1,  [x30, #0]
    ldp x2,  x3,  [x30, #16]
    ldp x4,  x5,  [x30, #32]
    ldp x6,  x7,  [x30, #48]
    ldp x8,  x9,  [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #ARM64_CTX_X30]
    eret
.size arm64_enter_el0, . - arm64_enter_el0

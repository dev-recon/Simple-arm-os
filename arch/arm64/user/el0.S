/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * First AArch64 EL0 entry and position-independent smoke-test payload.
 */

.section .text
.align 4
.global arm64_enter_el0
.type arm64_enter_el0, %function
arm64_enter_el0:
    msr elr_el1, x0
    msr sp_el0, x1
    mov x2, #0x3c0
    msr spsr_el1, x2
    isb
    eret
.size arm64_enter_el0, . - arm64_enter_el0

.align 4
.global arm64_el0_payload_start
.global arm64_el0_payload_end
.type arm64_el0_payload_start, %function
arm64_el0_payload_start:
    mov x0, #0x1234
    svc #0x64
    sub sp, sp, #16
    str x0, [sp]
    mov x0, xzr
    ldr x0, [sp]
    add sp, sp, #16
    movz x1, #0x1000
    movk x1, #0x40, lsl #16
    str x0, [x1]
    svc #0x65
1:
    b 1b
arm64_el0_payload_end:
.size arm64_el0_payload_start, . - arm64_el0_payload_start

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
.equ ARMOS_NR_EXIT,  1
.equ ARMOS_NR_WRITE, 4
.equ ARMOS_NR_UNKNOWN_TEST, 511
.equ ARM64_TEST_MESSAGE_LENGTH, 23

arm64_el0_payload_start:
    movz x3, #0x1000
    movk x3, #0x40, lsl #16

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    mov x1, x3
    mov x2, #ARM64_TEST_MESSAGE_LENGTH
    svc #0
    sub sp, sp, #16
    str x0, [sp]
    mov x0, xzr
    ldr x0, [sp]
    add sp, sp, #16
    str x0, [x3, #0x100]

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    movz x1, #0
    movk x1, #0x50, lsl #16
    mov x2, #1
    svc #0
    str x0, [x3, #0x108]

    mov x8, #ARMOS_NR_UNKNOWN_TEST
    svc #0
    str x0, [x3, #0x110]

    mov x8, #ARMOS_NR_EXIT
    mov x0, #42
    svc #0
1:
    b 1b
arm64_el0_payload_end:
.size arm64_el0_payload_start, . - arm64_el0_payload_start

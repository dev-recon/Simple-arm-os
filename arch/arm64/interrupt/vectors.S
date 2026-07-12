/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * ARMv8-A EL1 vector table and full general-register exception frame.
 */

.equ ARM64_EXC_FRAME_SIZE, 288

.section .vectors, "ax"
.balign 2048
.global arm64_vectors
.type arm64_vectors, %function

arm64_vectors:
    b arm64_vector_sync_sp0
    .balign 128
    b arm64_vector_irq_sp0
    .balign 128
    b arm64_vector_fiq_sp0
    .balign 128
    b arm64_vector_serror_sp0
    .balign 128

    b arm64_vector_sync_spx
    .balign 128
    b arm64_vector_irq_spx
    .balign 128
    b arm64_vector_fiq_spx
    .balign 128
    b arm64_vector_serror_spx
    .balign 128

    b arm64_vector_sync_lower_a64
    .balign 128
    b arm64_vector_irq_lower_a64
    .balign 128
    b arm64_vector_fiq_lower_a64
    .balign 128
    b arm64_vector_serror_lower_a64
    .balign 128

    b arm64_vector_sync_lower_a32
    .balign 128
    b arm64_vector_irq_lower_a32
    .balign 128
    b arm64_vector_fiq_lower_a32
    .balign 128
    b arm64_vector_serror_lower_a32
    .balign 128

.size arm64_vectors, . - arm64_vectors

.section .text
.align 4
.extern arm64_exception_dispatch

.macro ARM64_VECTOR_HANDLER name, number
\name:
    sub sp, sp, #ARM64_EXC_FRAME_SIZE
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    mov x16, #\number
    b arm64_vector_save_rest
.endm

ARM64_VECTOR_HANDLER arm64_vector_sync_sp0, 0
ARM64_VECTOR_HANDLER arm64_vector_irq_sp0, 1
ARM64_VECTOR_HANDLER arm64_vector_fiq_sp0, 2
ARM64_VECTOR_HANDLER arm64_vector_serror_sp0, 3
ARM64_VECTOR_HANDLER arm64_vector_sync_spx, 4
ARM64_VECTOR_HANDLER arm64_vector_irq_spx, 5
ARM64_VECTOR_HANDLER arm64_vector_fiq_spx, 6
ARM64_VECTOR_HANDLER arm64_vector_serror_spx, 7
ARM64_VECTOR_HANDLER arm64_vector_sync_lower_a64, 8
ARM64_VECTOR_HANDLER arm64_vector_irq_lower_a64, 9
ARM64_VECTOR_HANDLER arm64_vector_fiq_lower_a64, 10
ARM64_VECTOR_HANDLER arm64_vector_serror_lower_a64, 11
ARM64_VECTOR_HANDLER arm64_vector_sync_lower_a32, 12
ARM64_VECTOR_HANDLER arm64_vector_irq_lower_a32, 13
ARM64_VECTOR_HANDLER arm64_vector_fiq_lower_a32, 14
ARM64_VECTOR_HANDLER arm64_vector_serror_lower_a32, 15

arm64_vector_save_rest:
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    mrs x17, elr_el1
    str x17, [sp, #248]
    mrs x17, spsr_el1
    str x17, [sp, #256]
    mrs x17, esr_el1
    str x17, [sp, #264]
    mrs x17, far_el1
    str x17, [sp, #272]
    str x16, [sp, #280]

    mov x0, sp
    bl arm64_exception_dispatch

    ldr x16, [sp, #248]
    msr elr_el1, x16
    ldr x16, [sp, #256]
    msr spsr_el1, x16

    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    add sp, sp, #ARM64_EXC_FRAME_SIZE
    eret

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
 * - Enter EL0 from a scheduled generic task's owned kernel stack.
 * - Provide the position-independent syscall ABI smoke-test payload.
 * - Provide a bounded compute payload for timer-preemption validation.
 *
 * Notes:
 * - The payload is copied to an RX user page during early bring-up.
 * - Its yield syscall can resume through the preserved lower-EL frame.
 * - Context offsets are generated from the C layout by asm-offsets.c.
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

.align 4
.global arm64_user_task_probe_entry
.type arm64_user_task_probe_entry, %function
arm64_user_task_probe_entry:
    mov x0, x19
    bl arm64_user_task_probe_enter
1:
    wfe
    b 1b
.size arm64_user_task_probe_entry, . - arm64_user_task_probe_entry

.align 4
.global arm64_el0_payload_start
.global arm64_el0_payload_end
.type arm64_el0_payload_start, %function
.equ ARMOS_NR_EXIT,  1
.equ ARMOS_NR_FORK,  2
.equ ARMOS_NR_READ,  3
.equ ARMOS_NR_WRITE, 4
.equ ARMOS_NR_OPEN,  5
.equ ARMOS_NR_CLOSE, 6
.equ ARMOS_NR_WAITPID, 7
.equ ARMOS_NR_EXECVE, 11
.equ ARMOS_NR_GETPID, 20
.equ ARMOS_NR_KILL, 37
.equ ARMOS_NR_PIPE, 42
.equ ARMOS_NR_BRK, 45
.equ ARMOS_NR_DUP2, 63
.equ ARMOS_NR_SIGACTION, 67
.equ ARMOS_NR_SCHED_YIELD, 158
.equ ARMOS_NR_MMAP, 195
.equ ARMOS_NR_MUNMAP, 196
.equ ARMOS_NR_UNKNOWN_TEST, 511
.equ ARM64_TEST_MESSAGE_LENGTH, 23

arm64_el0_payload_start:
    movz x18, #0x1000
    movk x18, #0x40, lsl #16

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    mov x1, x18
    mov x2, #ARM64_TEST_MESSAGE_LENGTH
    svc #0
    sub sp, sp, #16
    str x0, [sp]
    mov x0, xzr
    ldr x0, [sp]
    add sp, sp, #16
    str x0, [x18, #0x100]

    mov x8, #ARMOS_NR_SCHED_YIELD
    svc #0

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    movz x1, #0
    movk x1, #0x50, lsl #16
    mov x2, #1
    svc #0
    str x0, [x18, #0x108]

    mov x8, #ARMOS_NR_UNKNOWN_TEST
    svc #0
    str x0, [x18, #0x110]

    adr x4, 2f
    str x4, [x18, #0x118]
    mov x8, #ARMOS_NR_EXIT
    mov x0, #42
    svc #0
2:
1:
    b 1b

.align 4
.global arm64_el0_preempt_payload
.type arm64_el0_preempt_payload, %function
arm64_el0_preempt_payload:
    movz x3, #0x1000
    movk x3, #0x40, lsl #16
    movz x9, #0
    movk x9, #0x0800, lsl #16
3:
    ldr w11, [x3, #0x300]
    cbnz w11, 5f
    subs x9, x9, #1
    b.ne 3b
    mov x0, #44
    b 6f
5:
    mov w12, #2
    str w12, [x3, #0x300]
    dmb ish
    mov x0, #43
6:
    msr nzcv, xzr
    mov x8, #ARMOS_NR_EXIT
    svc #0
4:
    b 4b
.size arm64_el0_preempt_payload, . - arm64_el0_preempt_payload

.align 4
.global arm64_el0_generic_payload
.type arm64_el0_generic_payload, %function
arm64_el0_generic_payload:
    movz x18, #0x1000
    movk x18, #0x40, lsl #16

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    mov x1, x18
    mov x2, #ARM64_TEST_MESSAGE_LENGTH
    svc #0
    str x0, [x18, #0x100]

    mov x8, #ARMOS_NR_SCHED_YIELD
    svc #0

    mov x8, #ARMOS_NR_WRITE
    mov x0, #1
    movz x1, #0
    movk x1, #0x50, lsl #16
    mov x2, #1
    svc #0
    str x0, [x18, #0x108]

    mov x8, #ARMOS_NR_UNKNOWN_TEST
    svc #0
    str x0, [x18, #0x110]

    mov x8, #ARMOS_NR_GETPID
    svc #0
    str x0, [x18, #0x120]

    mov x0, #10
    mov x1, #0x1234
    mov x2, xzr
    mov x8, #ARMOS_NR_SIGACTION
    svc #0
    str x0, [x18, #0x150]

    mov x8, #ARMOS_NR_FORK
    svc #0
    str x0, [x18, #0x158]

    mov x0, #2
    mov x1, #10
    mov x8, #ARMOS_NR_KILL
    svc #0
    str x0, [x18, #0x160]

    mov x0, #2
    mov x1, xzr
    mov x2, #1
    mov x8, #ARMOS_NR_WAITPID
    svc #0
    str x0, [x18, #0x168]

    movz x0, #0x1000
    movk x0, #0x0800, lsl #16
    mov x8, #ARMOS_NR_BRK
    svc #0
    str x0, [x18, #0x128]
    sub x6, x0, #8
    movz x7, #0x4d36
    movk x7, #0x5456, lsl #16
    movk x7, #0x554c, lsl #32
    movk x7, #0x4641, lsl #48
    str x7, [x6]
    ldr x9, [x6]
    str x9, [x18, #0x130]

    mov x0, xzr
    mov x1, #4096
    mov x2, #3
    mov x3, #0x22
    mov x4, #-1
    mov x5, xzr
    mov x8, #ARMOS_NR_MMAP
    svc #0
    str x0, [x18, #0x138]
    mov x6, x0
    str x7, [x6]
    ldr x9, [x6]
    str x9, [x18, #0x140]

    mov x0, x6
    mov x1, #4096
    mov x8, #ARMOS_NR_MUNMAP
    svc #0
    str x0, [x18, #0x148]

    add x0, x18, #0x380
    mov x1, xzr
    mov x2, xzr
    mov x8, #ARMOS_NR_OPEN
    svc #0
    mov x21, x0

    mov x0, x21
    add x1, x18, #0x3c0
    mov x2, #12
    mov x8, #ARMOS_NR_READ
    svc #0
    str x0, [x18, #0x170]

    mov x0, x21
    mov x8, #ARMOS_NR_CLOSE
    svc #0
    str x0, [x18, #0x178]

    add x0, x18, #0x400
    mov x8, #ARMOS_NR_PIPE
    svc #0
    str x0, [x18, #0x180]

    ldr w21, [x18, #0x400]
    ldr w22, [x18, #0x404]
    mov w0, w22
    add x1, x18, #0x420
    mov x2, #6
    mov x8, #ARMOS_NR_WRITE
    svc #0
    str x0, [x18, #0x188]

    mov w0, w21
    add x1, x18, #0x440
    mov x2, #6
    mov x8, #ARMOS_NR_READ
    svc #0
    str x0, [x18, #0x190]

    mov w0, w21
    mov x8, #ARMOS_NR_CLOSE
    svc #0
    mov w0, w22
    mov x8, #ARMOS_NR_CLOSE
    svc #0

    mov x0, #1
    mov x1, #9
    mov x8, #ARMOS_NR_DUP2
    svc #0
    str x0, [x18, #0x198]

    mov x0, #9
    mov x8, #ARMOS_NR_CLOSE
    svc #0

    adr x4, 2f
    str x4, [x18, #0x118]
    mov x8, #ARMOS_NR_EXIT
    mov x0, #42
    svc #0
2:
1:
    b 1b
.size arm64_el0_generic_payload, . - arm64_el0_generic_payload

.align 4
.global arm64_el0_exec_payload
.type arm64_el0_exec_payload, %function
arm64_el0_exec_payload:
    movz x18, #0x1000
    movk x18, #0x40, lsl #16
    add x0, x18, #0x480
    add x1, x18, #0x4a0
    add x2, x18, #0x4b0
    mov x8, #ARMOS_NR_EXECVE
    svc #0

    mov x0, #127
    mov x8, #ARMOS_NR_EXIT
    svc #0
1:
    b 1b
.size arm64_el0_exec_payload, . - arm64_el0_exec_payload

arm64_el0_payload_end:
.size arm64_el0_payload_start, . - arm64_el0_payload_start

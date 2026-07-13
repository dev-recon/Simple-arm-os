/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/task/context_switch.S
 * Layer: ARM64 / task switching
 *
 * Responsibilities:
 * - Save and restore AAPCS64 kernel callee-saved registers and stack state.
 * - Provide a deterministic two-context bootstrap probe.
 *
 * Notes:
 * - Address-space activation and scheduling policy are deliberately separate.
 * - Offsets come from arm64_task_context_t through asm-offsets.c.
 */

.include "asm-offsets.h"

.section .text
.align 4
.global arm64_task_context_switch
.type arm64_task_context_switch, %function
arm64_task_context_switch:
    stp x19, x20, [x0, #ARM64_TASK_X19]
    stp x21, x22, [x0, #ARM64_TASK_X21]
    stp x23, x24, [x0, #ARM64_TASK_X23]
    stp x25, x26, [x0, #ARM64_TASK_X25]
    stp x27, x28, [x0, #ARM64_TASK_X27]
    stp x29, x30, [x0, #ARM64_TASK_X29]
    mov x2, sp
    str x2, [x0, #ARM64_TASK_SP]
    adr x2, .Lcontext_resume
    str x2, [x0, #ARM64_TASK_PC]

    ldr x2, [x1, #ARM64_TASK_PC]
    ldr x3, [x1, #ARM64_TASK_SP]
    ldp x19, x20, [x1, #ARM64_TASK_X19]
    ldp x21, x22, [x1, #ARM64_TASK_X21]
    ldp x23, x24, [x1, #ARM64_TASK_X23]
    ldp x25, x26, [x1, #ARM64_TASK_X25]
    ldp x27, x28, [x1, #ARM64_TASK_X27]
    ldp x29, x30, [x1, #ARM64_TASK_X29]
    mov sp, x3
    br x2

.Lcontext_resume:
    ret
.size arm64_task_context_switch, . - arm64_task_context_switch

/*
 * Initial probe state:
 *   x19 = probe context, x20 = bootstrap context, x21 = phase address
 *   x22/x23 = preservation sentinels
 */
.align 4
.global arm64_task_context_probe_entry
.type arm64_task_context_probe_entry, %function
arm64_task_context_probe_entry:
    mov x9, #1
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_context_switch

    ldr x9, =0x2222222222222222
    cmp x22, x9
    b.ne .Lprobe_failed
    ldr x9, =0x2323232323232323
    cmp x23, x9
    b.ne .Lprobe_failed

    mov x9, #3
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_context_switch
    b .Lprobe_halt

.Lprobe_failed:
    mov x9, #0xff
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_context_switch

.Lprobe_halt:
    wfe
    b .Lprobe_halt
.size arm64_task_context_probe_entry, . - arm64_task_context_probe_entry

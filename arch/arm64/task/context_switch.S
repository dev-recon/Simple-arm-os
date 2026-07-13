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
 * - Preserve all FP/SIMD registers plus FPCR and FPSR between tasks.
 * - Provide deterministic context, dispatcher, and preemption peer probes.
 *
 * Notes:
 * - Address-space activation is performed by task_context.c before entry.
 * - Scheduling policy remains deliberately separate from this mechanism.
 * - Offsets come from arm64_task_context_t through asm-offsets.c.
 */

.include "asm-offsets.h"

.section .text
.align 4
.global arm64_task_context_switch
.type arm64_task_context_switch, %function
arm64_task_context_switch:
    stp q0,  q1,  [x0, #ARM64_TASK_SIMD_Q0 + 0]
    stp q2,  q3,  [x0, #ARM64_TASK_SIMD_Q0 + 32]
    stp q4,  q5,  [x0, #ARM64_TASK_SIMD_Q0 + 64]
    stp q6,  q7,  [x0, #ARM64_TASK_SIMD_Q0 + 96]
    stp q8,  q9,  [x0, #ARM64_TASK_SIMD_Q0 + 128]
    stp q10, q11, [x0, #ARM64_TASK_SIMD_Q0 + 160]
    stp q12, q13, [x0, #ARM64_TASK_SIMD_Q0 + 192]
    stp q14, q15, [x0, #ARM64_TASK_SIMD_Q0 + 224]
    stp q16, q17, [x0, #ARM64_TASK_SIMD_Q0 + 256]
    stp q18, q19, [x0, #ARM64_TASK_SIMD_Q0 + 288]
    stp q20, q21, [x0, #ARM64_TASK_SIMD_Q0 + 320]
    stp q22, q23, [x0, #ARM64_TASK_SIMD_Q0 + 352]
    stp q24, q25, [x0, #ARM64_TASK_SIMD_Q0 + 384]
    stp q26, q27, [x0, #ARM64_TASK_SIMD_Q0 + 416]
    stp q28, q29, [x0, #ARM64_TASK_SIMD_Q0 + 448]
    stp q30, q31, [x0, #ARM64_TASK_SIMD_Q0 + 480]
    mrs x2, fpcr
    str x2, [x0, #ARM64_TASK_SIMD_FPCR]
    mrs x2, fpsr
    str x2, [x0, #ARM64_TASK_SIMD_FPSR]

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

    ldr x3, [x1, #ARM64_TASK_SP]
    ldp x19, x20, [x1, #ARM64_TASK_X19]
    ldp x21, x22, [x1, #ARM64_TASK_X21]
    ldp x23, x24, [x1, #ARM64_TASK_X23]
    ldp x25, x26, [x1, #ARM64_TASK_X25]
    ldp x27, x28, [x1, #ARM64_TASK_X27]
    ldp x29, x30, [x1, #ARM64_TASK_X29]
    ldp q0,  q1,  [x1, #ARM64_TASK_SIMD_Q0 + 0]
    ldp q2,  q3,  [x1, #ARM64_TASK_SIMD_Q0 + 32]
    ldp q4,  q5,  [x1, #ARM64_TASK_SIMD_Q0 + 64]
    ldp q6,  q7,  [x1, #ARM64_TASK_SIMD_Q0 + 96]
    ldp q8,  q9,  [x1, #ARM64_TASK_SIMD_Q0 + 128]
    ldp q10, q11, [x1, #ARM64_TASK_SIMD_Q0 + 160]
    ldp q12, q13, [x1, #ARM64_TASK_SIMD_Q0 + 192]
    ldp q14, q15, [x1, #ARM64_TASK_SIMD_Q0 + 224]
    ldp q16, q17, [x1, #ARM64_TASK_SIMD_Q0 + 256]
    ldp q18, q19, [x1, #ARM64_TASK_SIMD_Q0 + 288]
    ldp q20, q21, [x1, #ARM64_TASK_SIMD_Q0 + 320]
    ldp q22, q23, [x1, #ARM64_TASK_SIMD_Q0 + 352]
    ldp q24, q25, [x1, #ARM64_TASK_SIMD_Q0 + 384]
    ldp q26, q27, [x1, #ARM64_TASK_SIMD_Q0 + 416]
    ldp q28, q29, [x1, #ARM64_TASK_SIMD_Q0 + 448]
    ldp q30, q31, [x1, #ARM64_TASK_SIMD_Q0 + 480]
    ldr x2, [x1, #ARM64_TASK_SIMD_FPCR]
    msr fpcr, x2
    ldr x2, [x1, #ARM64_TASK_SIMD_FPSR]
    msr fpsr, x2
    ldr x2, [x1, #ARM64_TASK_PC]
    mov sp, x3
    br x2

.Lcontext_resume:
    ret
.size arm64_task_context_switch, . - arm64_task_context_switch

.align 4
.global arm64_task_kernel_entry_trampoline
.type arm64_task_kernel_entry_trampoline, %function
arm64_task_kernel_entry_trampoline:
    mov x0, x20
    blr x19
1:
    wfe
    b 1b
.size arm64_task_kernel_entry_trampoline, . - arm64_task_kernel_entry_trampoline

.align 4
.global arm64_task_user_entry_trampoline
.type arm64_task_user_entry_trampoline, %function
arm64_task_user_entry_trampoline:
    mov x0, x19
    b arm64_enter_el0
.size arm64_task_user_entry_trampoline, . - arm64_task_user_entry_trampoline

.align 4
.global arm64_simd_context_capture
.type arm64_simd_context_capture, %function
arm64_simd_context_capture:
    stp q0,  q1,  [x0, #0]
    stp q2,  q3,  [x0, #32]
    stp q4,  q5,  [x0, #64]
    stp q6,  q7,  [x0, #96]
    stp q8,  q9,  [x0, #128]
    stp q10, q11, [x0, #160]
    stp q12, q13, [x0, #192]
    stp q14, q15, [x0, #224]
    stp q16, q17, [x0, #256]
    stp q18, q19, [x0, #288]
    stp q20, q21, [x0, #320]
    stp q22, q23, [x0, #352]
    stp q24, q25, [x0, #384]
    stp q26, q27, [x0, #416]
    stp q28, q29, [x0, #448]
    stp q30, q31, [x0, #480]
    mrs x1, fpcr
    str x1, [x0, #512]
    mrs x1, fpsr
    str x1, [x0, #520]
    ret
.size arm64_simd_context_capture, . - arm64_simd_context_capture

/*
 * Initial probe state:
 *   x19 = probe task, x20 = bootstrap task, x21 = phase address
 *   x22/x23 = preservation sentinels, x24 = observed TTBR0 address
 */
.align 4
.global arm64_task_context_probe_entry
.type arm64_task_context_probe_entry, %function
arm64_task_context_probe_entry:
    umov x9, v0.d[0]
    ldr x10, =0x0123456789abcdef
    cmp x9, x10
    b.ne .Lprobe_failed
    umov x9, v31.d[1]
    ldr x10, =0xfedcba9876543210
    cmp x9, x10
    b.ne .Lprobe_failed
    mrs x9, fpcr
    mov x10, #0x400000
    cmp x9, x10
    b.ne .Lprobe_failed
    mrs x9, fpsr
    cmp x9, #1
    b.ne .Lprobe_failed

    mrs x9, ttbr0_el1
    str x9, [x24]
    mov x9, #1
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_switch

    mrs x9, ttbr0_el1
    str x9, [x24]
    ldr x9, =0x2222222222222222
    cmp x22, x9
    b.ne .Lprobe_failed
    ldr x9, =0x2323232323232323
    cmp x23, x9
    b.ne .Lprobe_failed
    umov x9, v0.d[0]
    ldr x10, =0x0123456789abcdef
    cmp x9, x10
    b.ne .Lprobe_failed
    umov x9, v31.d[1]
    ldr x10, =0xfedcba9876543210
    cmp x9, x10
    b.ne .Lprobe_failed
    mrs x9, fpcr
    mov x10, #0x400000
    cmp x9, x10
    b.ne .Lprobe_failed
    mrs x9, fpsr
    cmp x9, #1
    b.ne .Lprobe_failed

    mov x9, #3
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_switch
    b .Lprobe_halt

.Lprobe_failed:
    mov x9, #0xff
    str x9, [x21]
    mov x0, x19
    mov x1, x20
    bl arm64_task_switch

.Lprobe_halt:
    wfe
    b .Lprobe_halt
.size arm64_task_context_probe_entry, . - arm64_task_context_probe_entry

/*
 * Dispatcher probe state:
 *   x21 = phase address, x22/x23 = preservation sentinels
 *   x25 = task_dispatcher_t pointer
 */
.align 4
.global arm64_task_dispatcher_probe_entry
.type arm64_task_dispatcher_probe_entry, %function
arm64_task_dispatcher_probe_entry:
    mov x9, #1
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_yield

    ldr x9, =0x2222222222222222
    cmp x22, x9
    b.ne .Ldispatcher_probe_failed
    ldr x9, =0x2323232323232323
    cmp x23, x9
    b.ne .Ldispatcher_probe_failed

    mov x9, #3
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block
    b .Ldispatcher_probe_halt

.Ldispatcher_probe_failed:
    mov x9, #0xff
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block

.Ldispatcher_probe_halt:
    wfe
    b .Ldispatcher_probe_halt
.size arm64_task_dispatcher_probe_entry, . - arm64_task_dispatcher_probe_entry

/*
 * EL0 preemption peer state:
 *   x21 = phase address, x22/x23 = preservation sentinels
 *   x25 = task_dispatcher_t pointer, x26 = user-visible completion flag
 */
.align 4
.global arm64_task_preempt_peer_entry
.type arm64_task_preempt_peer_entry, %function
arm64_task_preempt_peer_entry:
    mov x9, #1
    str x9, [x21]
    str x9, [x26]
    dmb ish
    mov x0, x25
    bl task_dispatcher_yield

    ldr x9, =0x2222222222222222
    cmp x22, x9
    b.ne .Lpreempt_peer_failed
    ldr x9, =0x2323232323232323
    cmp x23, x9
    b.ne .Lpreempt_peer_failed

    mov x9, #3
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block
    b .Lpreempt_peer_halt

.Lpreempt_peer_failed:
    mov x9, #0xff
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block

.Lpreempt_peer_halt:
    wfe
    b .Lpreempt_peer_halt
.size arm64_task_preempt_peer_entry, . - arm64_task_preempt_peer_entry

/*
 * Bounded periodic peer state:
 *   x21 = phase address, x22/x23 = preservation sentinels
 *   x25 = task_dispatcher_t pointer, x26 = user handshake flag
 */
.align 4
.global arm64_task_periodic_peer_entry
.type arm64_task_periodic_peer_entry, %function
arm64_task_periodic_peer_entry:
    mov x9, #1
    str x9, [x21]
    str x9, [x26]
    dmb ish
    msr daifclr, #2
    isb

.Lperiodic_peer_wait:
    ldr x9, [x26]
    cmp x9, #2
    b.lo .Lperiodic_peer_wait
    msr daifset, #2
    isb

    ldr x9, =0x2222222222222222
    cmp x22, x9
    b.ne .Lperiodic_peer_failed
    ldr x9, =0x2323232323232323
    cmp x23, x9
    b.ne .Lperiodic_peer_failed

    mov x9, #3
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block
    b .Lperiodic_peer_halt

.Lperiodic_peer_failed:
    mov x9, #0xff
    str x9, [x21]
    mov x0, x25
    bl task_dispatcher_block

.Lperiodic_peer_halt:
    wfe
    b .Lperiodic_peer_halt
.size arm64_task_periodic_peer_entry, . - arm64_task_periodic_peer_entry

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
 *   x19 = probe task, x20 = bootstrap task, x21 = phase address
 *   x22/x23 = preservation sentinels, x24 = observed TTBR0 address
 */
.align 4
.global arm64_task_context_probe_entry
.type arm64_task_context_probe_entry, %function
arm64_task_context_probe_entry:
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

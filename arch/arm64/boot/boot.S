/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/boot/boot.S
 * Layer: ARM64 / early boot
 *
 * Responsibilities:
 * - Normalize QEMU virt entry from EL2 or EL1 into the EL1h kernel context.
 * - Establish the boot stack, clear BSS and install the first vector table.
 * - Enable the AArch64 FP/SIMD register file for EL0 and EL1 execution.
 * - Transfer execution between the low bootstrap and high TTBR1 alias.
 *
 * Notes:
 * - Secondary CPUs remain parked until the ARM64 SMP startup path is added.
 */

.section .text.boot
.align 7
.global _start
.type _start, %function

.extern arm64_bootstrap_main
.extern arm64_vectors
.extern __bss_start
.extern __bss_end
.extern __stack_top

_start:
    msr daifset, #0xf

    /* Preserve the QEMU DTB pointer while establishing the execution level. */
    mov x20, x0

    mrs x1, mpidr_el1
    and x1, x1, #0xff
    cbnz x1, .Lsecondary_park

    mrs x1, CurrentEL
    lsr x1, x1, #2
    cmp x1, #2
    b.eq .Ldrop_from_el2
    cmp x1, #1
    b.eq .Lenter_el1
    b .Lbad_el

.Ldrop_from_el2:
    /* Run EL1 as AArch64 and return with interrupts masked on the EL1h stack. */
    mov x2, #(1 << 31)
    msr hcr_el2, x2
    mrs x2, cnthctl_el2
    orr x2, x2, #3
    msr cnthctl_el2, x2
    msr cntvoff_el2, xzr
    mov x2, #0x3c5
    msr spsr_el2, x2
    adr x2, .Lenter_el1
    msr elr_el2, x2
    ldr x2, =__stack_top
    msr sp_el1, x2
    eret

.Lenter_el1:
    msr spsel, #1
    isb
    ldr x1, =__stack_top
    mov sp, x1

    /* Newlib may use FP/SIMD even when an application is integer-only. */
    mrs x1, cpacr_el1
    orr x1, x1, #(3 << 20)
    msr cpacr_el1, x1
    isb
    msr fpcr, xzr
    msr fpsr, xzr

    ldr x1, =__bss_start
    ldr x2, =__bss_end
.Lclear_bss:
    cmp x1, x2
    b.hs .Lbss_done
    str xzr, [x1], #8
    b .Lclear_bss

.Lbss_done:
    ldr x1, =arm64_vectors
    msr vbar_el1, x1
    isb

    mov x0, x20
    bl arm64_bootstrap_main

.Lhalt:
    wfe
    b .Lhalt

.Lsecondary_park:
    wfe
    b .Lsecondary_park

.Lbad_el:
    wfe
    b .Lbad_el

.size _start, . - _start

/*
 * Continue execution through the TTBR1 kernel alias.  The caller supplies
 * the high entry PC, stack, vector base and one context argument.
 */
.global arm64_enter_high_alias
.type arm64_enter_high_alias, %function
arm64_enter_high_alias:
    mov x4, x0
    mov sp, x1
    msr vbar_el1, x2
    isb
    mov x0, x3
    br x4

.size arm64_enter_high_alias, . - arm64_enter_high_alias

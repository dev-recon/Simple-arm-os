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
 * - Normalize firmware/QEMU entry from EL3, EL2 or EL1 into EL1h.
 * - Establish the boot stack, clear BSS and install the first vector table.
 * - Reset firmware-owned CPU-local task state before entering common C code.
 * - Enable the AArch64 FP/SIMD register file for EL0 and EL1 execution.
 * - Transfer execution from the physical entry mapping to the common kernel.
 *
 * Notes:
 * - Secondary CPUs wait in a firmware-safe holding pen until common SMP code
 *   releases them onto private early stacks.
 */

.section .text.boot
.align 7
.global _start
.type _start, %function

.extern kernel_main
.extern arm64_vectors
.extern __bss_start
.extern __bss_end
.extern __stack_top
.extern __smp_stack_bottom
.extern arm64_mmu_enable_secondary
.extern smp_boot_gate
.extern smp_secondary_main
.extern smp_secondary_release_entry

.ifdef ARMOS_PLATFORM_RASPI3
/*
 * Cortex-A53 CPUECTLR_EL1.SMPEN controls intra-cluster data coherency.
 * The Cortex-A53 TRM requires it to be set before enabling the caches.
 * QEMU virt uses a Cortex-A72 and must not access this implementation-defined
 * A53 register.
 */
.macro arm64_enable_a53_smp scratch
    mrs \scratch, S3_1_C15_C2_1
    orr \scratch, \scratch, #(1 << 6)
    msr S3_1_C15_C2_1, \scratch
    isb
.endm
.else
.macro arm64_enable_a53_smp scratch
.endm
.endif

_start:
    msr daifset, #0xf

    /* Preserve the QEMU DTB pointer while establishing the execution level. */
    mov x20, x0

    mrs x1, mpidr_el1
    and x1, x1, #0xff
    cbnz x1, .Lsecondary_wait_release

    mrs x1, CurrentEL
    lsr x1, x1, #2
    cmp x1, #3
    b.eq .Ldrop_from_el3
    cmp x1, #2
    b.eq .Ldrop_from_el2
    cmp x1, #1
    b.eq .Lenter_el1
    b .Lbad_el

.Ldrop_from_el3:
    /*
     * QEMU raspi3b resets CPU0 in secure EL3 when a raw image is loaded.
     * Real Raspberry Pi firmware enters the kernel in EL2, so this path is
     * normally QEMU-only. Enter non-secure AArch64 EL2 with HVC enabled and
     * let the established EL2 path perform the final transition to EL1h.
     */
    mov x2, #0x501              /* SCR_EL3: NS | HCE | RW */
    msr scr_el3, x2
    msr cptr_el3, xzr
    mov x2, #0x3c9              /* Mask DAIF, return to EL2h. */
    msr spsr_el3, x2
    adr x2, .Ldrop_from_el2
    msr elr_el3, x2
    ldr x2, =__stack_top
    msr sp_el2, x2
    isb
    eret

.Ldrop_from_el2:
    arm64_enable_a53_smp x2
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
    msr tpidr_el1, xzr
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
    ldr x1, =dtb_address
    str x20, [x1]

    ldr x1, =arm64_vectors
    msr vbar_el1, x1
    isb

    /* Publish completed BSS/vector initialization to eager firmware cores. */
    ldr x1, =smp_boot_gate
    ldr x2, =0x534d505245414459
    str x2, [x1]
    dsb sy
    sev

    bl kernel_main

.Lhalt:
    wfe
    b .Lhalt

.Lsecondary_wait_release:
    ldr x2, =smp_boot_gate
    ldr x3, =0x534d505245414459
.Lsecondary_wait_boot:
    ldr x4, [x2]
    cmp x4, x3
    b.eq .Lsecondary_wait_entry
    wfe
    b .Lsecondary_wait_boot

.Lsecondary_wait_entry:
    ldr x2, =smp_secondary_release_entry
    ldr x5, [x2, x1, lsl #3]
    cbnz x5, .Lsecondary_branch_entry
    wfe
    b .Lsecondary_wait_entry

.Lsecondary_branch_entry:
    br x5

.Lbad_el:
    wfe
    b .Lbad_el

.size _start, . - _start

.align 4
.global smp_secondary_entry
.type smp_secondary_entry, %function
smp_secondary_entry:
    msr daifset, #0xf
    mrs x1, mpidr_el1
    and x1, x1, #0xff
    mov x19, x1

    ldr x2, =__smp_stack_bottom
    mov x3, #0x4000
    madd x2, x1, x3, x2
    add x2, x2, x3

    mrs x4, CurrentEL
    lsr x4, x4, #2
    cmp x4, #3
    b.eq .Lsecondary_drop_from_el3
    cmp x4, #2
    b.eq .Lsecondary_drop_from_el2
    cmp x4, #1
    b.eq .Lsecondary_enter_el1
    b .Lsecondary_halt

.Lsecondary_drop_from_el3:
    mov x4, #0x501
    msr scr_el3, x4
    msr cptr_el3, xzr
    mov x4, #0x3c9
    msr spsr_el3, x4
    adr x4, .Lsecondary_drop_from_el2
    msr elr_el3, x4
    msr sp_el2, x2
    isb
    eret

.Lsecondary_drop_from_el2:
    arm64_enable_a53_smp x4
    mov x4, #(1 << 31)
    msr hcr_el2, x4
    mrs x4, cnthctl_el2
    orr x4, x4, #3
    msr cnthctl_el2, x4
    msr cntvoff_el2, xzr
    mov x4, #0x3c5
    msr spsr_el2, x4
    adr x4, .Lsecondary_enter_el1
    msr elr_el2, x4
    msr sp_el1, x2
    eret

.Lsecondary_enter_el1:
    msr spsel, #1
    msr tpidr_el1, xzr
    isb
    mov sp, x2

    mrs x4, cpacr_el1
    orr x4, x4, #(3 << 20)
    msr cpacr_el1, x4
    isb
    msr fpcr, xzr
    msr fpsr, xzr

    ldr x4, =arm64_vectors
    msr vbar_el1, x4
    isb

    bl arm64_mmu_enable_secondary
    cbnz w0, .Lsecondary_halt
    mov x0, x19
    bl smp_secondary_main

.Lsecondary_halt:
    wfe
    b .Lsecondary_halt

.size smp_secondary_entry, . - smp_secondary_entry

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

.section .data
.align 3
.global dtb_address
.type dtb_address, %object
dtb_address:
    .quad 0
.size dtb_address, . - dtb_address

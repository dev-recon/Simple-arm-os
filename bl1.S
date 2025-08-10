@ bl1.s - Bootloader minimal pour QEMU secure mode
@ Syntaxe assembleur GNU ARM

.section .text
.global _start

@ ===== VECTEURS D'EXCEPTION (obligatoires pour bl1.bin) =====
.org 0x0
exception_vectors:
    b _start                     @ Reset vector
    b hang                       @ Undefined instruction
    b hang                       @ SVC
    b hang                       @ Prefetch abort
    b hang                       @ Data abort
    nop                          @ Reserved
    b hang                       @ IRQ
    b hang                       @ FIQ

@ Handler pour exceptions non gerees
hang:
    b hang                       @ Boucle infinie

@ ===== CODE PRINCIPAL BOOTLOADER =====
.org 0x40
_start:
    @ 1. Configurer le mode securise
    mrc p15, 0, r0, c1, c1, 0    @ Lire SCR
    bic r0, r0, #0x1             @ Clear NS bit
    orr r0, r0, #0x10            @ Set HCE bit
    mcr p15, 0, r0, c1, c1, 0    @ Ecrire SCR
    
    @ 2. Configurer le GIC en mode securise
    ldr r1, =0x1E001000          @ GICD_BASE
    mov r0, #0x3                 @ Enable Group 0 + Group 1
    str r0, [r1, #0x0]           @ GICD_CTLR = 0x3
    
    @ Configurer ITARGETSR pour CPU 0
    ldr r1, =0x1E001800          @ GICD_ITARGETSR base
    mov r0, #0x01                @ CPU 0
    
    @ Configurer IRQ 30-50 pour CPU 0
    mov r2, #30
itargetsr_loop:
    strb r0, [r1, r2]            @ ITARGETSR[r2] = 0x01
    add r2, r2, #1
    cmp r2, #51
    blt itargetsr_loop
    
    @ 3. Configurer les stacks
    cps #0x13                    @ Mode superviseur
    ldr sp, =0x6000F000          @ Stack superviseur
    
    cps #0x12                    @ Mode IRQ
    ldr sp, =0x6000E000          @ Stack IRQ
    
    cps #0x11                    @ Mode FIQ
    ldr sp, =0x6000D000          @ Stack FIQ
    
    @ Retour en mode superviseur
    cps #0x13
    
    @ 4. Activer les IRQ globalement
    cpsie aif                    @ Enable IRQ, FIQ, Abort
    
    @ 5. Message de debug
    ldr r0, =secure_msg
    bl debug_print
    
    @ 6. Sauter au kernel
    ldr pc, =0x60010000          @ Adresse kernel

@ ===== FONCTION DEBUG UART =====
debug_print:
    ldr r1, =0x10009000          @ UART base
debug_loop:
    ldrb r2, [r0], #1
    cmp r2, #0
    beq debug_done
    str r2, [r1]                 @ Ecrire caractere
    b debug_loop
debug_done:
    bx lr

@ ===== DONNEES =====
secure_msg:
    .ascii "BL1: Secure mode configured, jumping to kernel...\n"
    .byte 0

.align 4
.end


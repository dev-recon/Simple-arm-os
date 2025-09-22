/* interrupt.S - Gestionnaire d'interruptions pour machine virt - VERSION CORRIGeE */

.section .text
.align 2

.global irq_handler
.global swi_handler

irq_handler:
    /* Ajuster LR pour retour d'exception */
    sub     lr, lr, #4

    /* Sauvegarder r0-r12 et lr sur la pile IRQ (banked SP) */
    stmfd   sp!, {r0-r12, lr}    /* 14 regs => 56 bytes (pile reste alignée) */

    /* Sauvegarder SPSR */
    mrs     r0, spsr
    stmfd   sp!, {r0}            /* +4 bytes => maintenant pile désalignée */

    /* Padding 4 octets pour aligner la pile à 8 avant appel C */
    sub     sp, sp, #4           /* maintenant (56+4+4)=64 bytes => alignée 8 */

    /* Passer l'adresse du contexte à la C handler (r0 = &saved_spsr/pile) */
    mov     r0, sp               /* r0 pointe sur la zone pad (utilisable en C pour index) */
    bl      irq_c_handler

    /* Retirer le padding (on retourne à l'adresse de SPSR) */
    add     sp, sp, #4

    /* Restaurer SPSR */
    ldmfd   sp!, {r0}            /* pop saved_spsr */
    msr     spsr_cxsf, r0

    /* Restaurer r0-r12 et revenir en utilisant '^' pour restaurer CPSR depuis SPSR */
    ldmfd   sp!, {r0-r12, pc}^

/* IRQ Handler pour machine virt avec GICv2 */
irq_handler2:
    /* Save context sur la pile IRQ */
    sub lr, lr, #4              /* Ajuster LR pour IRQ */
    stmfd sp!, {r0-r12, lr}     /* Sauvegarder registres */
    mrs r0, spsr                /* Recuperer SPSR */
    stmfd sp!, {r0}             /* Sauvegarder SPSR */

    /* Padding 4 octets pour aligner la pile à 8 avant appel C */
    sub     sp, sp, #4           /* maintenant (56+4+4)=64 bytes => alignée 8 */

    /* Desactiver les interruptions pendant le traitement */
    cpsid i
    
    /* Appeler le handler C avec context */
    bl irq_c_handler
    
    /* Retirer le padding (on retourne à l'adresse de SPSR) */
    add     sp, sp, #4

    /* Restaurer le contexte */
    ldmfd sp!, {r0}             /* Restaurer SPSR */
    msr spsr_cxsf, r0
    ldmfd sp!, {r0-r12, lr}     /* Restaurer registres */
    
    /* Retourner du handler IRQ */
    movs pc, lr

/* Fast IRQ Handler pour machine virt */
.global fiq_handler
fiq_handler:
    /* FIQ a ses propres registres r8-r14 */
    sub lr, lr, #4              /* Ajuster LR pour FIQ */
    stmfd sp!, {r0-r7, lr}      /* Sauvegarder uniquement r0-r7 */
    mrs r0, spsr
    stmfd sp!, {r0}
    
    /* Padding 4 octets pour aligner la pile à 8 avant appel C */
    sub     sp, sp, #4           /* maintenant (56+4+4)=64 bytes => alignée 8 */

    /* Appeler le handler C rapide */
    bl fiq_c_handler
    
    /* Retirer le padding (on retourne à l'adresse de SPSR) */
    add     sp, sp, #4

    /* Restaurer */
    ldmfd sp!, {r0}
    msr spsr_cxsf, r0
    ldmfd sp!, {r0-r7, lr}
    
    /* Retourner du FIQ */
    movs pc, lr

/* Functions pour la gestion du GICv2 sur machine virt */
.global gic_cpu_interface_init
gic_cpu_interface_init:
    /* r0 = GIC CPU base address (0x08010000 sur virt) */
    
    /* Activer l'interface CPU du GIC */
    mov r1, #1
    str r1, [r0, #0x00]         /* GICC_CTLR = 1 (enable) */
    
    /* Configurer la priorite minimale */
    mov r1, #0xF0
    str r1, [r0, #0x04]         /* GICC_PMR = 0xF0 */
    
    /* Configurer le binary point */
    mov r1, #3
    str r1, [r0, #0x08]         /* GICC_BPR = 3 */
    
    bx lr

.global gic_distributor_init
gic_distributor_init:
    /* r0 = GIC Distributor base address (0x08000000 sur virt) */
    
    /* Desactiver le distributeur pendant la configuration */
    mov r1, #0
    str r1, [r0, #0x00]         /* GICD_CTLR = 0 */
    
    /* Lire le nombre d'IRQs supportees */
    ldr r1, [r0, #0x04]         /* GICD_TYPER */
    and r1, r1, #0x1F           /* Extract ITLinesNumber */
    add r1, r1, #1              /* Nombre de groupes de 32 IRQs */
    mov r2, #32
    mul r3, r1, r2              /* Total number of IRQs - corriger mul */
    
    /* Desactiver toutes les IRQs */
    mov r2, #0
    mov r1, #0x80               /* GICD_ICENABLER0 offset */
gic_disable_loop:
    str r2, [r0, r1]
    add r1, r1, #4
    subs r3, r3, #32
    bgt gic_disable_loop
    
    /* Configurer les priorites par defaut */
    ldr r1, =0xA0A0A0A0         /* Priority 0xA0 pour toutes - CORRIGe */
    mov r2, #0x400              /* GICD_IPRIORITYR0 offset */
    mov r3, #0
gic_priority_loop:
    str r1, [r0, r2]
    add r2, r2, #4
    add r3, r3, #4
    cmp r3, #0x400              /* 256 IRQs max */
    blt gic_priority_loop
    
    /* Activer le distributeur */
    mov r1, #1
    str r1, [r0, #0x00]         /* GICD_CTLR = 1 */
    
    bx lr

/* Lecture de l'IRQ active depuis le GIC */
.global gic_get_active_irq
gic_get_active_irq:
    /* r0 = GIC CPU base address */
    ldr r0, [r0, #0x0C]         /* GICC_IAR */
    ldr r1, =0x3FF              /* Mask pour IRQ number - CORRIGe */
    and r0, r0, r1              /* Appliquer le mask */
    bx lr

/* Acknowledger une IRQ */
.global gic_ack_irq
gic_ack_irq:
    /* r0 = GIC CPU base address, r1 = IRQ number */
    str r1, [r0, #0x10]         /* GICC_EOIR */
    bx lr

/* Activer une IRQ specifique */
.global gic_enable_irq
gic_enable_irq:
    /* r0 = GIC Distributor base, r1 = IRQ number */
    
    /* Calculer l'offset et le bit */
    mov r2, r1, lsr #5          /* r2 = IRQ / 32 */
    and r3, r1, #31             /* r3 = IRQ % 32 */
    mov r4, #1
    lsl r4, r4, r3              /* r4 = 1 << (IRQ % 32) - CORRIGe */
    
    /* Activer l'IRQ */
    add r2, r2, #0x100          /* GICD_ISENABLER0 offset */
    str r4, [r0, r2, lsl #2]
    
    bx lr

/* Desactiver une IRQ specifique */
.global gic_disable_irq
gic_disable_irq:
    /* r0 = GIC Distributor base, r1 = IRQ number */
    
    /* Calculer l'offset et le bit */
    mov r2, r1, lsr #5          /* r2 = IRQ / 32 */
    and r3, r1, #31             /* r3 = IRQ % 32 */
    mov r4, #1
    lsl r4, r4, r3              /* r4 = 1 << (IRQ % 32) - CORRIGe */
    
    /* Desactiver l'IRQ */
    add r2, r2, #0x180          /* GICD_ICENABLER0 offset */
    str r4, [r0, r2, lsl #2]
    
    bx lr

/* Timer functions pour machine virt (ARM Generic Timers) */
.global timer_get_frequency
timer_get_frequency:
    /* Lire la frequence du timer generique */
    mrc p15, 0, r0, c14, c0, 0  /* CNTFRQ */
    bx lr

.global timer_get_count
timer_get_count:
    /* Lire le compteur physique */
    mrrc p15, 0, r0, r1, c14    /* CNTPCT (64-bit) */
    bx lr

.global timer_set_compare
timer_set_compare:
    /* r0 = low 32 bits, r1 = high 32 bits */
    mcrr p15, 2, r0, r1, c14    /* CNTP_CVAL */
    bx lr

.global timer_enable
timer_enable:
    mrc p15, 0, r0, c14, c2, 1  /* CNTP_CTL */
    orr r0, r0, #1              /* Enable bit */
    mcr p15, 0, r0, c14, c2, 1
    bx lr

.global timer_disable
timer_disable:
    mrc p15, 0, r0, c14, c2, 1  /* CNTP_CTL */
    bic r0, r0, #1              /* Clear enable bit */
    mcr p15, 0, r0, c14, c2, 1
    bx lr

/* Cache management functions pour Cortex-A15 */
.global flush_dcache_range
flush_dcache_range:
    /* r0 = start address, r1 = end address */
    
    /* Get cache line size */
    mrc p15, 0, r2, c0, c0, 1   /* Read CCSIDR */
    and r2, r2, #7              /* Extract log2(line_size) - 4 */
    mov r3, #16
    lsl r3, r3, r2              /* r3 = cache line size - CORRIGe */
    
    /* Align start address */
    sub r2, r3, #1
    bic r0, r0, r2
    
flush_loop:
    mcr p15, 0, r0, c7, c14, 1  /* DCCIMVAC - clean & invalidate */
    add r0, r0, r3
    cmp r0, r1
    blt flush_loop
    
    dsb
    bx lr

.global invalidate_icache_all
invalidate_icache_all:
    mov r0, #0
    mcr p15, 0, r0, c7, c5, 0   /* ICIALLU */
    dsb
    isb
    bx lr

/* Memory barriers optimisees pour Cortex-A15 */
.global memory_barrier_full
memory_barrier_full:
    dsb sy                      /* Data Synchronization Barrier */
    isb                         /* Instruction Synchronization Barrier */
    bx lr

.global memory_barrier_read
memory_barrier_read:
    dsb ld                      /* Load barrier */
    bx lr

.global memory_barrier_write
memory_barrier_write:
    dsb st                      /* Store barrier */
    bx lr

.end

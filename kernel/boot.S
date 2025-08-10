/*
 * boot.S - ARMv7-A Cortex-A15 kernel boot
 * Adapte pour machine QEMU virt
 * Alignement strict pour eviter les Heisenbugs
 */
.global _start
.global vectors
.global dtb_address

.extern data_abort_handler
.extern undefined_instruction_handler
.extern prefetch_abort_handler
.extern swi_handler


/*
 * Point d'entree du kernel - appele par QEMU
 * R0 = DTB address (Device Tree Blob)
 * R1 = Machine type (legacy)
 * R2 = ATAG address (legacy)
 */
_start:
    /* === PHASE 1: SAUVEGARDE ET VeRIFICATIONS === */
    
    /* Sauvegarder le DTB address immediatement */
    ldr r3, =dtb_address
    str r0, [r3]
    
    /* Verifier qu'on est sur le CPU principal (Core 0) */
    mrc p15, 0, r0, c0, c0, 5   /* Lire MPIDR (Multiprocessor Affinity Register) */
    and r0, r0, #3              /* Extraire CPU ID (bits 1:0) */
    cmp r0, #0                  /* CPU 0 ? */
    bne halt_secondary_cpu      /* Arreter les autres CPUs */
    
    /* === PHASE 2: CONFIGURATION SeCURITe === */
    
    /* Desactiver toutes les interruptions */
    cpsid if                    /* Disable IRQ and FIQ */
    
    /* Configuration systeme de base */
    bl setup_cpu_state
    
    /* === PHASE 3: CONFIGURATION PILE ALIGNeE === */
    
    /* CRITIQUE: Configuration pile avec alignement strict */
    ldr sp, =__stack_top
    
    /* CORRECTION HEISENBUG: Forcer alignement 8 bytes */
    and sp, sp, #~7             /* Clear les 3 bits de poids faible */

    /* === CONFIGURATION PILE DU MODE ABT === */
    cps #0x17                 /* Passer en mode ABT (0b100111) */
    ldr sp, =__abt_stack_top  /* Charger le SP du mode ABT */

    /* Initialiser pile IRQ */
    cps #0x12         /* mode IRQ */
    ldr sp, =__irq_stack_top

    /* Initialiser pile SVC */
    cps #0x13
    ldr r0, =__stack_top   /* Charge l'adresse */
    mov sp, r0                   /* Puis dans SP */
    and sp, sp, #~7              /* Alignement */
    /*ldr sp, =__svc_stack_top
    and sp, sp, #~7    */          /* Force 8-byte alignment */
    
    /* Verification de securite: SP dans la bonne plage */
    ldr r0, =__stack_bottom
    cmp sp, r0
    blo stack_panic             /* SP trop bas = erreur fatale */
    
    ldr r0, =__stack_top
    add r0, r0, #32             /* Marge de securite */
    cmp sp, r0  
    bhi stack_panic             /* SP trop haut = erreur fatale */
    
    /* === PHASE 4: VECTEURS D'INTERRUPTION === */
    
    /* Configurer la table des vecteurs */
    ldr r0, =vectors
    mcr p15, 0, r0, c12, c0, 0  /* ecrire VBAR (Vector Base Address Register) */
    dsb                         /* Data Synchronization Barrier */
    isb                         /* Instruction Synchronization Barrier */
    
    /* === PHASE 5: INITIALISATION MeMOIRE === */
    
    /* Effacer la section BSS (variables non-initialisees) */
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0                  /* Valeur de remplissage */

clear_bss_loop:
    cmp r0, r1                  /* Fin de BSS atteinte ? */
    strlo r2, [r0], #4          /* ecrire 0 et avancer de 4 bytes */
    blo clear_bss_loop          /* Continuer si pas fini */
    
    /* Restaurer l'adresse DTB apres clear BSS */
    ldr r3, =dtb_address
    ldr r0, [r3]
    str r0, [r3]                /* S'assurer que DTB est preserve */
    
    /* === PHASE 6: OPTIMISATIONS PERFORMANCE === */
    
    /* Activer les caches et optimisations */
    bl enable_caches_and_optimizations
    
    /* === PHASE 7: TRANSFERT AU KERNEL === */
    /* S'assurer qu'on est en mode SVC avec la bonne pile */
    cps #0x13                    /* Force mode SVC */
    ldr sp, =__stack_top         /* Pile principale kernel */
    and sp, sp, #~7              /* Force 8-byte alignment */
    
    /* Memory barriers finaux avant le kernel */
    dsb
    isb
    
    /* Appeler le kernel principal en C */
    bl kernel_main
    
    /* Ne devrait jamais atteindre ce point */
    b kernel_exit_panic

/*
 * Configuration avancee du CPU ARMv7-A Cortex-A15
 */
setup_cpu_state:
    /* Sauvegarder le registre de retour */
    mov r4, lr
    
    /* Lire SCTLR (System Control Register) */
    mrc p15, 0, r0, c1, c0, 0
    
    /* Configuration des bits critiques */
    bic r0, r0, #(1 << 0)       /* M: Desactiver MMU (sera activee plus tard) */
    bic r0, r0, #(1 << 2)       /* C: Desactiver data cache (temporaire) */
    bic r0, r0, #(1 << 12)      /* I: Desactiver instruction cache (temporaire) */
    
    /* Bits de securite et performance */
    orr r0, r0, #(1 << 1)       /* A: Activer l'alignement strict (CRITIQUE!) */
    orr r0, r0, #(1 << 11)      /* Z: Activer la prediction de branchement */
    bic r0, r0, #(1 << 13)      /* V: Utiliser basse adresse (VBAR) */
    
    /* ecrire la configuration */
    mcr p15, 0, r0, c1, c0, 0
    dsb
    isb
    
    /* Configuration additionnelle pour Cortex-A15 */
    
    /* ACTLR (Auxiliary Control Register) pour Cortex-A15 */
    mrc p15, 0, r0, c1, c0, 1
    orr r0, r0, #(1 << 6)       /* SMP: Coherency enable pour multi-core */
    orr r0, r0, #(1 << 0)       /* L1 data prefetch enable */
    mcr p15, 0, r0, c1, c0, 1
    
    /* Restaurer et retourner */
    mov lr, r4
    bx lr

/*
 * Activation des caches et optimisations Cortex-A15
 */
enable_caches_and_optimizations:
    mov r4, lr
    
    /* === PHASE 1: INVALIDATION COMPLeTE === */
    
    /* Invalider tous les caches */
    mov r0, #0
    mcr p15, 0, r0, c7, c7, 0   /* Invalidate entire cache */
    mcr p15, 0, r0, c8, c7, 0   /* Invalidate entire TLB */
    mcr p15, 0, r0, c7, c5, 6   /* Invalidate entire branch predictor */
    
    dsb
    isb
    
    /* === PHASE 2: CONFIGURATION CACHE L1 === */
    
    /* Lire SCTLR pour modification */
    mrc p15, 0, r0, c1, c0, 0
    
    /* Activer les caches et optimisations */
    orr r0, r0, #(1 << 2)       /* C: Data cache enable */
    orr r0, r0, #(1 << 12)      /* I: Instruction cache enable */
    orr r0, r0, #(1 << 11)      /* Z: Branch prediction enable */
    
    /* ecrire la configuration finale */
    mcr p15, 0, r0, c1, c0, 0
    dsb
    isb
    
    /* === PHASE 3: OPTIMISATIONS CORTEX-A15 === */
    
    /* Configuration performance avancee */
    mrc p15, 0, r0, c1, c0, 1   /* Lire ACTLR */
    orr r0, r0, #(1 << 6)       /* SMP: Coherency enable pour multi-core */
    mcr p15, 0, r0, c1, c0, 1   /* ecrire ACTLR */
    
    mov lr, r4
    bx lr

/*
 * Gestion des CPUs secondaires (multi-core)
 */
halt_secondary_cpu:
    /* CPU secondaire detecte - le mettre en attente */
    
    /* Obtenir l'ID du CPU */
    mrc p15, 0, r0, c0, c0, 5
    and r0, r0, #3
    
    /* Pour debug: vous pourriez signaler quel CPU est arrete */
    /* (necessiterait une fonction d'affichage) */
    
secondary_wait_loop:
    wfi                         /* Wait For Interrupt */
    b secondary_wait_loop       /* Boucle infinie */

/*
 * Gestion des erreurs critiques
 */
stack_panic:
    /* Stack pointer invalide detecte */
    /* En production, vous pourriez allumer une LED ou ecrire sur UART */
    
    /* Pour l'instant, arret immediat */
    b panic_halt

kernel_exit_panic:
    /* kernel_main() a retourne - ne devrait jamais arriver */
    b panic_halt

panic_halt:
    /* Arret d'urgence avec desactivation complete */
    cpsid if                    /* Desactiver toutes les interruptions */
    
panic_loop:
    wfi                         /* economiser l'energie */
    b panic_loop                /* Boucle infinie */

/*
 * Table des vecteurs d'interruption ARMv7-A
 * Alignee sur 32 bytes comme requis par l'architecture
 */
.section .vectors, "ax"
.align 5                        /* 2^5 = 32 bytes alignment */
.global vectors
vectors:
    b reset_vector          /* 0x00: Reset */
    b undefined_vector      /* 0x04: Undefined instruction */
    b swi_vector            /* 0x08: Software interrupt (SVC) */
    b prefetch_vector       /* 0x0C: Prefetch abort */
    b data_abort_vector     /* 0x10: Data abort */
    nop                     /* 0x14: Reserved vector */
    b irq_vector            /* 0x18: IRQ */
    b fiq_vector            /* 0x1C: FIQ */

/*
 * Gestionnaires d'exceptions
 */
reset_vector:
    /* Reset detecte - redemarrer */
    b _start

undefined_vector:
    /* Instruction non-definie */
    /* TODO: Implementer un handler proper avec diagnostic */
    b undefined_instruction_handler

swi_vector:
    /* Software interrupt (appels systeme) */
    /* TODO: Implementer le gestionnaire SVC */
    b swi_handler

prefetch_vector:
    /* Prefetch abort (erreur de fetch d'instruction) */
    /* TODO: Implementer diagnostic et recovery */
    b prefetch_abort_handler

data_abort_vector:
    sub lr, lr, #8               /* Corrige l'adresse de retour (ARM spec) */
    stmfd sp!, {r0-r12, lr}      /* Sauvegarde des registres */
    bl data_abort_handler        /* Appel du handler en C */
    ldmfd sp!, {r0-r12, lr}      /* Restauration des registres */
    subs pc, lr, #0              /* Retour de l'exception */

irq_vector:
    /* Interruption normale */
    /* TODO: Sauvegarder contexte et appeler handler C */
    ldr r0, =0xCAFEDEAD
    ldr r1, =0x09000000          /* UART virt address */
    str r0, [r1]
    b irq_handler

fiq_vector:
    /* Fast interrupt */
    /* TODO: Handler rapide */
    b exception_panic

exception_panic:
    /* Gestionnaire d'urgence pour exceptions non-gerees */
    /* En mode debug, vous pourriez afficher des informations */
    cpsid if                    /* Desactiver interruptions */
    b panic_loop               /* Arret s-r */

/* === FONCTIONS UTILITAIRES EXPORTeES VERS LE C === */

/*
 * =======================================================================
 * FONCTIONS MMIO - PUT32/GET32 et variantes
 * =======================================================================
 */

.global PUT32
.type PUT32, %function
PUT32:
    /* Arguments: r0 = address, r1 = value */
    push {r2, lr}
    dmb sy                      /* Data Memory Barrier */
    str r1, [r0]               /* Store 32-bit value */
    dsb sy                      /* Data Synchronization Barrier */
    pop {r2, lr}
    bx lr

.global GET32
.type GET32, %function
GET32:
    /* Arguments: r0 = address, Return: r0 = value */
    push {r1, lr}
    dmb sy
    ldr r0, [r0]               /* Load 32-bit value */
    dmb sy
    pop {r1, lr}
    bx lr

.global PUT8
.type PUT8, %function
PUT8:
    /* Arguments: r0 = address, r1 = value (8-bit) */
    push {r2, lr}
    dmb sy
    strb r1, [r0]              /* Store byte */
    dsb sy
    pop {r2, lr}
    bx lr

.global GET8
.type GET8, %function
GET8:
    /* Arguments: r0 = address, Return: r0 = value (8-bit) */
    push {r1, lr}
    dmb sy
    ldrb r0, [r0]              /* Load byte */
    dmb sy
    pop {r1, lr}
    bx lr

.global PUT16
.type PUT16, %function
PUT16:
    /* Arguments: r0 = address, r1 = value (16-bit) */
    push {r2, lr}
    dmb sy
    strh r1, [r0]              /* Store half-word */
    dsb sy
    pop {r2, lr}
    bx lr

.global GET16
.type GET16, %function
GET16:
    /* Arguments: r0 = address, Return: r0 = value (16-bit) */
    push {r1, lr}
    dmb sy
    ldrh r0, [r0]              /* Load half-word */
    dmb sy
    pop {r1, lr}
    bx lr

.global PUT32_STRONG
.type PUT32_STRONG, %function
PUT32_STRONG:
    /* Version avec barrieres renforcees pour MMIO critique */
    push {r2, lr}
    dsb sy
    dmb sy
    isb
    str r1, [r0]
    dsb sy
    dmb sy
    isb
    pop {r2, lr}
    bx lr

.global GET32_STRONG
.type GET32_STRONG, %function
GET32_STRONG:
    /* Version avec barrieres renforcees pour MMIO critique */
    push {r1, lr}
    dsb sy
    dmb sy
    isb
    ldr r0, [r0]
    dsb sy
    dmb sy
    isb
    pop {r1, lr}
    bx lr

.global TEST_MMIO
.type TEST_MMIO, %function
TEST_MMIO:
    /* Test si un registre est writable */
    /* Arguments: r0 = address, Return: r0 = 1 si writable, 0 sinon */
    push {r1, r2, r3, lr}
    
    mov r3, r0                  /* Sauver adresse */
    bl GET32                    /* Lire valeur originale */
    mov r1, r0                  /* r1 = original */
    
    /* Tester ecriture avec pattern simple */
    mov r0, r3
    ldr r2, =test_pattern       /* Charger pattern depuis litteral */
    push {r1}                   /* Sauver original */
    mov r1, r2
    bl PUT32
    
    /* Relire */
    mov r0, r3
    bl GET32
    mov r2, r0                  /* r2 = valeur relue */
    
    /* Restaurer */
    pop {r1}
    mov r0, r3
    bl PUT32
    
    /* Comparer avec le pattern */
    ldr r3, =test_pattern
    mov r0, #0                  /* echec par defaut */
    cmp r2, r3
    bne test_mmio_end
    mov r0, #1                  /* Succes */
    
test_mmio_end:
    pop {r1, r2, r3, lr}
    bx lr

/* Pattern de test en tant que litteral */
test_pattern:
    .word 0x12345678

/*
 * === SECTION DONNeES === 
 */
.section ".data"

/* Variable globale pour l'adresse DTB */
.align 4
.global dtb_address
dtb_address:
    .word 0

/*
 * === SECTION BSS (Variables non-initialisees) ===
 */
.section ".bss"

/* PILE DU KERNEL - ALIGNEMENT CRITIQUE POUR eVITER LES HEISENBUGS */
/*.align 8  */                      /* Force alignement section sur 256 bytes (2^8) */
/*.global stack_bottom*/
/*stack_bottom:*/
/*    .space 65536   */             /* 64KB de pile */
    
/*.align 3     */                   /* Force alignement sur 8 bytes (2^3) */
/*.global stack_top*/
/*stack_top:*/
/*    .space 16     */              /* Petit buffer de securite */

/*
 * Informations de build (optionnel)
 */
.section ".rodata"
.align 4
build_info:
    .ascii "ARM32-Kernel-Boot-v1.0-Virt-Cortex-A15\0"
    .align 4

/*
 * === FONCTIONS UTILITAIRES EXPORTeES VERS LE C ===
 */

/* Fonction pour obtenir l'ID du CPU actuel */
.global get_cpu_id
.type get_cpu_id, %function
get_cpu_id:
    mrc p15, 0, r0, c0, c0, 5   /* Lire MPIDR */
    and r0, r0, #3              /* Extraire CPU ID */
    bx lr

/* Fonction pour obtenir le registre SP actuel */
.global get_stack_pointer
.type get_stack_pointer, %function
get_stack_pointer:
    mov r0, sp                  /* Retourner SP dans R0 */
    bx lr

/* Fonction pour forcer un alignement du SP */
.global align_stack_pointer
.type align_stack_pointer, %function
align_stack_pointer:
    and sp, sp, #~7             /* Force 8-byte alignment */
    mov r0, sp                  /* Retourner le nouveau SP */
    bx lr

/* Fonction pour invalider les caches */
.global invalidate_caches
.type invalidate_caches, %function
invalidate_caches:
    mov r0, #0
    mcr p15, 0, r0, c7, c7, 0   /* Invalidate all caches */
    dsb
    isb
    bx lr

/* === MACROS DE DEBUG (conditionnelles) === */

#ifdef DEBUG_BOOT
    /* En mode debug, vous pourriez ajouter des points d'arret */
    .global debug_breakpoint
    debug_breakpoint:
        nop                     /* Point d'arret pour debugger */
        bx lr
#endif

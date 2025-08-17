/* kernel/syscalls/syscall.S - Version corrigee */

.section .text
.align 2

.global swi_handler
.global signal_return_trampoline
.equ __NR_rt_sigreturn, 173

/* ARM32 Software Interrupt Handler - Point d'entree principal */
swi_handler:
    /* Ajuster LR pour SWI et sauvegarder contexte */
    /*sub lr, lr, #4 */             /* Ajuster LR pour SWI */
    
    /* Debug entree dans syscall */
    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}

    stmfd sp!, {r0-r12, lr}     /* Sauvegarder registres + LR */
    mrs r12, spsr               /* Recuperer SPSR */
    stmfd sp!, {r12}            /* Sauvegarder SPSR */
    
    /* Validation du numero de syscall */
    cmp r7, #256                /* Verifier limite syscall */
    movhs r0, #-38              /* Si invalide: r0 = -ENOSYS */
    bhs syscall_return          /* Brancher vers retour direct */
    
    /* Arguments pour syscall_handler */
    /* Prototype: syscall_handler(syscall_num, arg1, arg2, arg3, arg4, arg5) */
    stmfd sp!, {r4, r5}         /* Placer arg4 et arg5 sur la pile */

    /* CORRECTION : Sauvegarder r0-r3 AVANT de les écraser */
    mov r6, r0                  /* r6 = arg0 original */
    mov r8, r1                  /* r8 = arg1 original */
    mov r9, r2                  /* r9 = arg2 original */
    mov r10, r3                 /* r10 = arg3 original */

    
    /* Maintenant configurer les paramètres pour syscall_handler */
    mov r0, r7                  /* r0 = numero syscall */
    mov r1, r6                  /* r1 = arg0 (fd) */
    mov r2, r8                  /* r2 = arg1 (buf) */
    mov r3, r9                  /* r3 = arg2 (count) */
    /* r4, r5 sur pile = arg3, arg4 */
    
    /* Verification stack overflow basique */
    cmp sp, #0x40000000         /* Verifier limite minimum pile kernel */
    blo stack_panic
    
    /* Appeler le handler C */
    bl syscall_handler
    
    /* Nettoyer la pile (arg4, arg5) */
    add sp, sp, #8

syscall_return:
    /* Restaurer contexte sans ecraser r0 */
    ldmfd sp!, {r12}            /* Restaurer SPSR */
    msr spsr_cxsf, r12
    
    /* Preserver r0 (valeur de retour) et restaurer le reste */
    ldmfd sp!, {r1}             /* Charger ancien r0 dans r1 (ignore) */
    ldmfd sp!, {r1-r12, lr}     /* Restaurer r1-r12, lr (r0 intact) */

    /* Debug sortie de syscall */
    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}
    
    /* Retourner en mode utilisateur */
    movs pc, lr

stack_panic:
    /* Gestion basique de stack overflow */
    mov r0, #-12                /* -ENOMEM */
    b syscall_return

/* Trampoline de signal plus robuste */
signal_return_trampoline:
    mov r7, #__NR_rt_sigreturn  /* __NR_rt_sigreturn */
    swi #0                      /* Declencher syscall */
    
    /* Si retour echoue, terminer proprement */
    mov r7, #1                  /* sys_exit */
    mov r0, #-1                 /* Code d'erreur */
    swi #0

/* Context switching simplifie */
.global context_switch_virt
context_switch_virt:
    /* Arguments: r0 = current_task, r1 = next_task */
    
    /* Verifications de securite */
    cmp r0, #0
    cmpne r1, #0
    bxeq lr                     /* Retour si pointeurs NULL */
    
    /* Sauvegarder le contexte de la tache actuelle */
    stmia r0, {r0-r14}^         /* Sauvegarder registres user mode */
    mrs r2, spsr
    str r2, [r0, #60]           /* Sauvegarder SPSR */
    
    /* Restaurer le contexte de la prochaine tache */
    ldr r2, [r1, #60]           /* Charger SPSR */
    msr spsr_cxsf, r2
    ldmia r1, {r0-r14}^         /* Restaurer registres user mode */
    
    /* Change address space si different */
    ldr r2, [r1, #64]           /* Charger TTBR0 */
    mrc p15, 0, r3, c2, c0, 0   /* Lire TTBR0 actuel */
    cmp r2, r3
    beq skip_ttbr_update        /* Skip si identique */
    
    mcr p15, 0, r2, c2, c0, 0   /* Ecrire nouveau TTBR0 */
    
    /* Invalider le TLB seulement si changement */
    mov r2, #0
    mcr p15, 0, r2, c8, c7, 0   /* Invalider TLB */
    
skip_ttbr_update:
    /* Barriers pour la coherence */
    dsb
    isb
    
    /* Retourner a la nouvelle tache */
    movs pc, lr

/* Fonctions helper optimisees */
.global save_user_context
save_user_context:
    /* Verifier pointeur */
    cmp r0, #0
    bxeq lr
    
    /* Sauvegarder le contexte utilisateur */
    stmia r0, {r0-r15}^         /* Sauvegarder r0-r15 en mode user */
    mrs r1, spsr
    str r1, [r0, #64]           /* Sauvegarder SPSR */
    
    bx lr

.global restore_user_context  
restore_user_context:
    /* Verifier pointeur */
    cmp r0, #0
    bxeq lr
    
    /* Restaurer le contexte utilisateur */
    ldr r1, [r0, #64]           /* Charger SPSR */
    msr spsr_cxsf, r1          /* Restaurer SPSR */
    ldmia r0, {r0-r15}^         /* Restaurer r0-r15 (mode user) */
    bx lr

/* Setup signal frame pour machine virt */
.global setup_signal_frame
setup_signal_frame:
    /* r0 = user_stack, r1 = signal_handler, r2 = signal_number */
    
    /* Creer le frame de signal sur la pile utilisateur */
    sub r0, r0, #256            /* Reserver espace pour le frame */
    
    /* Sauvegarder le contexte actuel dans le frame */
    stmia r0, {r0-r14}^         /* Sauvegarder registres user */
    mrs r3, spsr
    str r3, [r0, #60]           /* Sauvegarder SPSR */
    
    /* Configurer le retour de signal */
    ldr r3, =signal_return_trampoline
    str r3, [r0, #56]           /* LR = trampoline */
    
    /* Configurer les arguments du signal handler */
    mov r3, r2                  /* r3 = signal_number */
    mov r2, #0                  /* r2 = siginfo (NULL pour l'instant) */
    mov r1, #0                  /* r1 = ucontext (NULL pour l'instant) */
    mov r0, r3                  /* r0 = signal_number */
    
    bx lr

/* Cache management plus efficace */
.global flush_syscall_cache
flush_syscall_cache:
    /* Ordre optimal des operations */
    
    /* Data cache d'abord */
    mov r0, #0
    mcr p15, 0, r0, c7, c14, 0  /* Clean & Invalidate D-cache */
    
    /* Barrier avant instruction cache */
    dsb sy
    
    /* Instruction cache */
    mcr p15, 0, r0, c7, c5, 0   /* Invalidate I-cache */
    
    /* TLB en dernier */
    mcr p15, 0, r0, c8, c7, 0   /* Invalidate TLB */
    
    /* Barriers finaux */
    dsb sy
    isb
    
    bx lr

/* Performance counters conditionnels */
.global enable_performance_counters
enable_performance_counters:
    /* Verifier disponibilite */
    mrc p15, 0, r1, c0, c1, 2   /* Lire CLIDR */
    ands r1, r1, #0x7000000     /* Check cache levels */
    bxeq lr                     /* Retour si pas de cache */
    
    /* Activer les compteurs */
    mrc p15, 0, r0, c9, c12, 0  /* Lire PMCR */
    orr r0, r0, #7              /* Enable + Reset cycles + Reset events */
    mcr p15, 0, r0, c9, c12, 0  /* Ecrire PMCR */
    
    /* Activer le cycle counter */
    mov r0, #0x80000000
    mcr p15, 0, r0, c9, c12, 1  /* PMCNTENSET */
    
    bx lr

.global read_cycle_counter
read_cycle_counter:
    mrc p15, 0, r0, c9, c13, 0  /* PMCCNTR */
    bx lr

.end

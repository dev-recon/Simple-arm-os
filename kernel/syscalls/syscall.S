/* kernel/syscalls/syscall.S - Version corrigee */
#include <kernel/task.h>

.section .text
.align 2

.global swi_handler
.global current_task
//.global TASK_CONTEXT_OFF   //via l’en-tete pre-traite
.global save_user_bank
.global signal_return_trampoline
.equ __NR_rt_sigreturn, 173

    /* Registres generaux r0-r12 */
    // r0.         0,
    // r1          4,
    // r2          8,
    // r3          12
    // r4          16
    // r5          20
    // r6          24
    // r7          28
    // r8          32
    // r9          36
    // r10         40
    // r11         44
    // r12         48
    
    /* Registres speciaux */
    // sp          52       // Stack Pointer 
    // lr          56       // Link Register 
    // pc;         60       // Program Counter 
    // cpsr;       64       // Current Program Status Register 
    
    // is_first_run; 68.     // NOUVEAU: Flag pour premiere execution 
    // ttbr0;      72
    // asid;       76

    // spsr;       80        // SPSR_svc 
    // returns_to_user;  84  // has to return to user mode 

    // usr_r[0];     88      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[1];     92      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[2];     96      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[3];     100      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[4];     104      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[5];     108      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[6];     112      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[7];     116      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[8];     120      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[9];     124      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[10];    128      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[11];    132      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[12];    136      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_sp;       140
    // usr_lr;       144         // optionnel si tu l’utilises
    // usr_pc;       148         // point de reprise user
    // usr_cpsr;     152        // en général 0x10
    // svc_sp_top;   156        // haut de pile noyau allouée pour ce task
    // svc_sp;       160        // courant (si tu le tiens à jour)
    // svc_lr_saved; 164        // si tu en as besoin

/* ARM32 Software Interrupt Handler - Point d'entree principal */
swi_handler:

    stmfd sp!, {r4-r5, r7-r12, lr}     /* Sauvegarder registres + LR */
    mrs r12, spsr               /* Recuperer SPSR */
    stmfd sp!, {r12}            /* Sauvegarder SPSR */
    
    /* Debug sortie de syscall */
    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}

    /* Validation du numero de syscall */
    cmp r7, #256                /* Verifier limite syscall */
    movhs r0, #-38              /* Si invalide: r0 = -ENOSYS */
    bhs syscall_return          /* Brancher vers retour direct */
    
    /* Arguments pour syscall_handler */
    /* Prototype: syscall_handler(syscall_num, arg1, arg2, arg3, arg4, arg5) */

    /* 1) FigER immédiatement les registres USER dont on a besoin */
    /* On va les recopier dans le contexte, ainsi on peut clobber r0..r3 ensuite */
    ldr     r12, =current_task
    ldr     r12, [r12]               /* r12 = current_task */
    add     r12, r12, #48          /* r12 = &current->context */ // FIX IT !!!

    /* 1) Sauver IMMÉDIATEMENT les 4 args user AVANT toute modif */
    mov   r8,  r0              /* a0 */
    mov   r9,  r1              /* a1 */
    mov   r10, r2              /* a2 */
    mov   r6, r3              /* a3 (utilise r12 comme temp ici) */

    /* Copier 9 arguments user dans ctx->usr_r[0..7] + ctx->usr_r[11] */
    str     r0,  [r12, #(88 + 0)]
    str     r1,  [r12, #(88 + 4)]
    str     r2,  [r12, #(88 + 8)]
    str     r3,  [r12, #(88 + 12)]
    str     r4,  [r12, #(88 + 16)]   /* ATTENTION: r4/r5 = args4/5 du user ! */
    str     r5,  [r12, #(88 + 20)]
    str     r6,  [r12, #(88 + 24)]
    str     r7,  [r12, #(88 + 24)]
    str     r11,  [r12, #(88 + 44)]

    /* 2) Sauvegardes “banquées” essentielles (sans BL, donc pas de clobber imprévu) */
    mrs     r0, spsr
    str     r0,  [r12, #152]           /* CPSR du user */
    mov     r0,  lr
    str     r0,  [r12, #148]          /* PC de retour user = LR_svc (ARM) */
    str     r0,  [r12, #144]          /* PC de retour user = LR_svc (ARM) */

    cps     #0x1F                            /* passer en SYS pour lire SP_user */
    mov     r0,  sp
    cps     #0x13                            /* revenir en SVC */
    str     r0,  [r12, #140]

    mov     r0,  #1
    str     r0,  [r12, #84]         /* marquer retour vers USR */

    /* Préparer les arguments sur la pile pour syscall_handler */
    sub   sp, sp, #8           /* Allouer 8 octets pour 2 arguments sur pile */
    str   r4, [sp, #0]        /* [sp+0] = a4 (5ème param de syscall_handler) */
    str   r5, [sp, #4]         /* [sp+4] = a5 (6ème param de syscall_handler) */

    /* Préparer les 4 premiers arguments dans les registres */
    mov   r0, r7               /* r0 = num (1er param) */
    mov   r1, r8               /* r1 = a1  (2ème param) */
    mov   r2, r9               /* r2 = a2  (3ème param) */
    mov   r3, r10              /* r3 = a3  (4ème param) */

    /* Appeler le handler C */
    bl syscall_handler
    
syscall_return:
    /* r0 contient la valeur de retour du syscall.
       On la garde dans un temporaire pour restaurer proprement les registres. */
    mov   r6, r0
    /* Nettoyer la pile (arg4, arg5) */
    add sp, sp, #8

    /* Récupérer SPSR sauvegardé juste après {r0-r12,lr} */
    ldr     r12, [sp], #4       /* r12 = spsr_sauvé ; sp avance de 4 */
    msr     spsr_cxsf, r12

    /* Restaurer tous les registres du caller, y compris l'ancien r0 */
    ldmfd  sp!, {r4-r5, r7-r12, lr}

    //push {r0-r3, lr}
    //mov r0, r12
    //bl debug_print_sp
    //pop {r0-r3, lr}

    /* Remettre la valeur de retour dans r0 */
    mov     r0, r6

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


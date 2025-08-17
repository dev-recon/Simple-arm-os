/* kernel/task/task_switch.S - Commutation de contexte ARM Cortex-A15 */
.text
.align 4

/*
 * Structure task_context_t (offsets pour ARM32) :
 * r0-r6:   0-24    (7 registres × 4 bytes)
 * r7-r12:  28-48   (6 registres × 4 bytes)  
 * sp:      52      (4 bytes)
 * lr:      56      (4 bytes)
 * pc:      60      (4 bytes)
 * cpsr:    64      (4 bytes)
 * Total:   68 bytes
 */
.global __task_switch_to_user
.type __task_switch_to_user, %function

 __task_switch_to_user:
    /* Pas de sauvegarde - cette fonction ne retourne JAMAIS */
    //push {r0-r3, lr}
    //bl debug_print_sp
    //pop {r0-r3, lr}

    /* Pas de sauvegarde - cette fonction ne retourne JAMAIS */
    push {r4}                   @ Juste pour sauver un registre de travail
    
    /* Charger les valeurs du contexte */
    ldr r1, [r0, #60]           @ PC utilisateur (0x8000)
    ldr r2, [r0, #52]           @ SP utilisateur (0x3EFFFFFC)
    ldr r3, [r0, #64]           @ CPSR utilisateur (0x10)
    ldr r4, [r0, #0]            @ Premier argument (r0)
    
    /* ÉTAPE 1: Configurer SPSR pour le mode utilisateur */
    msr spsr_cxsf, r3           @ SPSR = mode user + flags
    
    /* ÉTAPE 2: Configurer le SP utilisateur */
    cps #0x1f                   @ Mode System
    mov sp, r2                  @ Configurer SP utilisateur
    cps #0x13                   @ Retour en mode SVC
    
    /* ÉTAPE 3: Barrière pour s'assurer que la MMU est synchronisée */
    dsb sy                      @ Attendre que toutes les écritures soient terminées
    isb                         @ Synchroniser le pipeline dinstructions
    
    /* ÉTAPE 4: Charger le registre r0 (argument) et sauter */
    mov r0, r4                  @ Premier argument 
    movs pc, r1                 @ CRITIQUE: movs change de mode selon SPSR
    
    /* Ne devrait jamais arriver ici */
    pop {r4}
    bx lr

.size __task_switch_to_user, . - __task_switch_to_user

/*
 * Premiere commutation systeme - Simple et directe
 * void __task_first_switch_v2(task_context_t* new_ctx)
 * 
 * Cette fonction est appelee UNE SEULE FOIS au demarrage du scheduler
 * pour commuter vers la premiere tache selectionnee.
 */

.global __task_first_switch_v2
.type __task_first_switch_v2, %function

__task_first_switch_v2:
    /* Premiere execution de la nouvelle tache */
    
    ldr r2, [r0, #64]           /* Restaurer CPSR */
    msr cpsr_c, r2
    
    ldr sp, [r0, #52]           /* Restaurer SP */
    
    /* Marquer comme non-premiere execution pour la prochaine fois */
    mov r2, #0
    str r2, [r0, #68]
    
    ldr r2, [r0, #60]           /* PC = adresse de la fonction d'entree */
    ldr r0, [r0, #0]            /* r0 = argument pour la fonction */
    
    mov lr, #0                  /* Pas de retour */
    /* === PROTECTION MAXIMALE === */
    /*push {r0-r12, lr}*/   /* Sauvegarder TOUS les registres */
    /*mov r4, sp */         /* Sauvegarder aussi SP */
    
    /*bl debug_print_sp2*/   /* Appel securise */
    
    /*mov sp, r4*/          /* Restaurer SP */
    /*pop {r0-r12, lr}*/    /* Restaurer TOUS les registres */
    bx r2                       /* Saut vers la fonction d'entree */

.size __task_first_switch_v2, . - __task_first_switch_v2


.global task_exit_wrapper
.type task_exit_wrapper, %function
task_exit_wrapper:
    /* Cette fonction est appelee quand une tache se termine */
    /* r0 contient deja l'argument de retour */
    
    /* Appeler task_destroy avec la tache courante */
    mov r0, #0              /* NULL = tache courante */
    bl task_destroy
    
    /* Ne devrait jamais revenir, mais au cas ou... */
    b task_exit_wrapper


/*
 * Commutation normale entre taches avec sauvegarde complete
 * void __task_switch_asm(task_context_t* old_ctx, task_context_t* new_ctx)
 * 
 * Cette fonction sauvegarde le contexte complet de la tache courante
 * et restaure le contexte de la nouvelle tache.
 */
.global __task_switch_asm_debug
.type __task_switch_asm_debug, %function

__task_switch_asm_debug:
    /* Entree : r0 = old_ctx, r1 = new_ctx */

    /* Verifications de securite */
    cmp r0, #0
    beq error_null_old_ctx_debug
    cmp r1, #0
    beq error_null_new_ctx_debug

    /* === SAUVEGARDE SeCURISeE === */
    /* IMPORTANT: Ne pas modifier r0 avant la sauvegarde complete */
    /* === PROTECTION MAXIMALE === */
    /*push {r0-r12, lr}*/   /* Sauvegarder TOUS les registres */
    /*ldr r4, [r0, #52]  */        /* Sauvegarder aussi SP */
    
    /*bl debug_print_sp*/   /* Appel securise */
    
    /*mov sp, r4   */       /* Restaurer SP */
    /*pop {r0-r12, lr}*/    /* Restaurer TOUS les registres */

    /* === SAUVEGARDE CORRIGeE === */
    
    /* Pour une premiere execution, le SP est deja dans le contexte */
    ldr r2, [r0, #68]           /* Charger is_first_run */
    cmp r2, #1
    beq save_first_run_context
    
    /* CORRECTION: Pour une tache suspendue, sauvegarder CORRECTEMENT */
    
    /* Sauvegarder r2-r12 d'abord (r0,r1 sont des parametres de fonction) */
    str r2, [r0, #8]            /* r2 */
    str r3, [r0, #12]           /* r3 */
    str r4, [r0, #16]           /* r4 */
    str r5, [r0, #20]           /* r5 */
    str r6, [r0, #24]           /* r6 */
    str r7, [r0, #28]           /* r7 */
    str r8, [r0, #32]           /* r8 */
    str r9, [r0, #36]           /* r9 */
    str r10, [r0, #40]          /* r10 */
    str r11, [r0, #44]          /* r11 */
    str r12, [r0, #48]          /* r12 */
    
    /* Pour r0 et r1, utiliser les valeurs SAUVEGARDeES dans le contexte */
    /* (Elles sont deja correctes depuis la derniere execution) */
    /* NE PAS ecraser r0 et r1 avec les parametres de fonction ! */
    
    str sp, [r0, #52]           /* SP actuel (OK pour tache suspendue) */
    str lr, [r0, #56]           /* LR */
    str lr, [r0, #60]           /* PC = LR */
    b save_context_common
    
save_first_run_context:
    /* Pour une premiere execution, ne pas ecraser le SP configure */
    
    /* CORRECTION: Pour premiere execution aussi ! */
    str r2, [r0, #8]            /* r2 */
    str r3, [r0, #12]           /* r3 */
    str r4, [r0, #16]           /* r4 */
    str r5, [r0, #20]           /* r5 */
    str r6, [r0, #24]           /* r6 */
    str r7, [r0, #28]           /* r7 */
    str r8, [r0, #32]           /* r8 */
    str r9, [r0, #36]           /* r9 */
    str r10, [r0, #40]          /* r10 */
    str r11, [r0, #44]          /* r11 */
    str r12, [r0, #48]          /* r12 */
    
    /* r0 et r1 sont deja configures dans setup_task_context() */
    /* NE PAS ecraser SP - il est deja correct dans le contexte */
    str lr, [r0, #56]           /* LR */
    str lr, [r0, #60]           /* PC = LR */
    
save_context_common:
    /* Sauvegarder CPSR */
    mrs r3, cpsr
    str r3, [r0, #64]
    
    /* Marquer comme non-premiere execution */
    mov r3, #0
    str r3, [r0, #68]

    /* === RESTAURATION === */
    ldr r2, [r1, #68]           /* Charger is_first_run de new_ctx */
    cmp r2, #1
    beq first_execution_debug
    b restore_suspended_debug

first_execution_debug:
    /* Premiere execution de la nouvelle tache */
    
    ldr r2, [r1, #64]           /* Restaurer CPSR */
    msr cpsr_c, r2
    
    ldr sp, [r1, #52]           /* Restaurer SP */
    
    /* Marquer comme non-premiere execution pour la prochaine fois */
    mov r2, #0
    str r2, [r1, #68]
    
    ldr r2, [r1, #60]           /* PC = adresse de la fonction d'entree */
    ldr r0, [r1, #0]            /* r0 = argument pour la fonction */
    
    mov lr, #0                  /* Pas de retour */
    /* === PROTECTION MAXIMALE === */
    //push {r0-r3, lr}          /* CORRECTION: Moins de registres pour debug */
    
    //bl debug_print_sp  /* Appel securise */
    
    //pop {r0-r3, lr}           /* Restaurer seulement ce qu'on a push */
    bx r2                      /* Saut vers la fonction d'entree */

restore_suspended_debug:
    /* Restauration d'une tache suspendue */
    
    ldr r2, [r1, #64]           /* Restaurer CPSR */
    msr cpsr_c, r2
    
    ldr sp, [r1, #52]           /* Restaurer SP */
    ldr lr, [r1, #56]           /* Restaurer LR */
    ldr r2, [r1, #60]           /* Charger PC */
    
    /* CORRECTION: Restaurer TOUS les registres correctement */
    ldr r0, [r1, #0]            /* r0 */
    ldr r3, [r1, #12]           /* r3 (on utilise r2 pour PC) */
    ldr r4, [r1, #16]           /* r4 */
    ldr r5, [r1, #20]           /* r5 */
    ldr r6, [r1, #24]           /* r6 */
    ldr r7, [r1, #28]           /* r7 */
    ldr r8, [r1, #32]           /* r8 */
    ldr r9, [r1, #36]           /* r9 */
    ldr r10, [r1, #40]          /* r10 */
    ldr r11, [r1, #44]          /* r11 */
    ldr r12, [r1, #48]          /* r12 */
    
    /* Enfin r1 */
    push {r2}                   /* Sauvegarder PC temporairement */
    ldr r1, [r1, #4]            /* r1 */
    pop {r2}                    /* Restaurer PC */
    
    /* Debug apres restauration */
    //push {r0-r3, lr}
    //bl debug_print_sp
    //pop {r0-r3, lr}
    
    bx r2                       /* Reprendre l'execution */

error_null_old_ctx_debug:
    bl debug_null_old_ctx
    mov r0, r1              /* Continuer avec new_ctx */
    b first_execution_debug

error_null_new_ctx_debug:
    bl debug_null_new_ctx
    b error_null_new_ctx_debug  /* Boucle infinie */

.size __task_switch_asm_debug, . - __task_switch_asm_debug

/*
 * Informations de debug (visibles dans objdump)
 */
.section .rodata
task_switch_info:
    .ascii "ARM32 Task Switch v1.0 - Cortex-A15 Optimized\0"
    .ascii "Context size: 68 bytes\0"
    .ascii "Supports: Full context save/restore\0"


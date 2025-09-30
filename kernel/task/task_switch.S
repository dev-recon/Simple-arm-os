/* kernel/task/task_switch.S - Commutation de contexte ARM Cortex-A15 */
.text
.align 4

.global current_task

/* ---------------- Offsets (structure task_context_t) ---------------- */
    .equ CTX_R0,              0      /* r0 */
    .equ CTX_R1,              4
    .equ CTX_R2,              8
    .equ CTX_R3,             12
    .equ CTX_R4,             16
    .equ CTX_R5,             20
    .equ CTX_R6,             24
    .equ CTX_R7,             28
    .equ CTX_R8,             32
    .equ CTX_R9,             36
    .equ CTX_R10,            40
    .equ CTX_R11,            44
    .equ CTX_R12,            48
    .equ CTX_SP,             52
    .equ CTX_LR,             56
    .equ CTX_PC,             60
    .equ CTX_CPSR,           64
    .equ CTX_FIRST,          68      /* is_first_run */
    .equ CTX_TTBR0,          72
    .equ CTX_ASID,           76
    .equ CTX_SPSR,           80      /* spsr_svc (si utilisé) */
    .equ CTX_RET_TO_USER,    84      /* returns_to_user */
    .equ CTX_USR_R0,         88
    .equ CTX_USR_R1,         92
    .equ CTX_USR_R2,         96
    .equ CTX_USR_R3,        100
    .equ CTX_USR_R4,        104
    .equ CTX_USR_R5,        108
    .equ CTX_USR_R6,        112
    .equ CTX_USR_R7,        116
    .equ CTX_USR_R8,        120
    .equ CTX_USR_R9,        124
    .equ CTX_USR_R10,       128
    .equ CTX_USR_R11,       132
    .equ CTX_USR_R12,       136
    .equ CTX_USR_SP,        140
    .equ CTX_USR_LR,        144
    .equ CTX_USR_PC,        148
    .equ CTX_USR_CPSR,      152
    .equ CTX_SVC_SP_TOP,    156
    .equ CTX_SVC_SP,        160
    .equ CTX_SVC_LR_SAVED,  164
    .equ CTX_SIZE,          168


/*
 * task_switch - Commutation de tâche ARM32
 * 
 * IMPORTANT: Cette fonction ne retourne JAMAIS vers l'appelant !
 * Elle bascule directement vers la nouvelle tâche.
 * 
 * Paramètres:
 *   r0 = old_ctx (pointeur vers task_context_t de la tâche courante)
 *   r1 = new_ctx (pointeur vers task_context_t de la nouvelle tâche)
 * 
 * Gère tous les cas:
 *   - USR -> 1ère exécution
 *   - USR -> suspended  
 *   - SVC -> 1ère exécution
 *   - SVC -> suspended
 * 
 * PILE: Cette fonction modifie SP mais ne retourne jamais,
 *       donc pas de symétrie de pile nécessaire.
 */

 /*
 * task_switch - Commutation de tâche ARM32
 * 
 * OFFSETS DE LA STRUCTURE task_context_t:
 * r0-r6:           0-24
 * r7-r12:          28-48  
 * sp:              52
 * lr:              56
 * pc:              60
 * cpsr:            64
 * is_first_run:    68
 * ttbr0:           72
 * asid:            76
 * spsr:            80
 * returns_to_user: 84
 * usr_r[0-12]:     88-136
 * usr_sp:          140
 * usr_lr:          144
 * usr_pc:          148
 * usr_cpsr:        152
 * svc_sp_top:      156
 * svc_sp:          160
 * svc_lr_saved:    164
 */


.global __task_switch
.align 4
.type __task_switch, %function
.syntax unified


#define USE_RTUSR_SNAP 0

/* Entrée: r0 = old_ctx (ou 0), r1 = new_ctx */
/* r11 NE SERT PAS de temporaire ici. r12 = ctx base. */

__task_switch:
    /* ---------- PHASE 1 : SAUVEGARDE old_ctx ---------- */
    cmp     r0, #0
    beq     __load_new_context

    /* r0 = &old_ctx */
    stmia   r0, {r0-r12}                   // save r0..r12

    /* Retourne-t-on en mode utilisateur ? */
    ldr     r2, [r0, #CTX_RET_TO_USER]
    cmp     r2, #1
    beq     __user_ctx

    str     sp, [r0, #CTX_SP]              // sp courant (pile kernel de la tâche)
    str     sp, [r0, #CTX_SVC_SP]          // sp courant (pile kernel de la tâche)

__user_ctx:
    str     lr, [r0, #CTX_LR]              // lr point de reprise
    str     lr, [r0, #CTX_PC]              // pc (option: identique au lr ici)
    mrs     r2, cpsr
    str     r2, [r0, #CTX_CPSR]            // cpsr
    mov     r2, #0
    str     r2, [r0, #CTX_FIRST]           // is_first_run = 0

    /* tenir usr_r[] en phase avec les regs CPU */
    //add     r3, r0, #CTX_USR_R0
    //stmia   r3, {r0-r12}                   // usr_r[0..12] = r0..r12

__load_new_context:
    /* ---------- PHASE 2 : CHARGEMENT new_ctx ---------- */
    mov     r12, r1                         // r12 = &new_ctx (base ctx)

    /* MMU context (si nécessaire) */
    ldr     r2, [r12, #CTX_TTBR0]
    ldr     r3, [r12, #CTX_ASID]
    mcr     p15, 0, r2, c2,  c0, 0         // TTBR0
    mcr     p15, 0, r3, c13, c0, 1         // ASID
    mov     r2, #0
    mcr     p15, 0, r2, c8,  c7, 0         // Invalidate TLB
    dsb
    isb

    /* -- insertion atomique update current_task -- */
    sub    r3, r12, #48    @ r12 est &new_ctx dans ton code ; r3 = next_task
    ldr    r2, =current_task
    str    r3, [r2]
    dmb

    /* Première exécution ? */
    ldr     r2, [r12, #CTX_FIRST]
    cmp     r2, #1
    beq     __first_run_setup

    /* Retourne-t-on en mode utilisateur ? */
    ldr     r2, [r12, #CTX_RET_TO_USER]
    cmp     r2, #1
    beq     __restore_to_user

    /* ---------- RESTORE KERNEL (tâche suspendue kernel) ---------- */
__restore_to_kernel:
    ldr     sp, [r12, #CTX_SP]             // pile kernel de la tâche
    ldr     r2, [r12, #CTX_CPSR]
    msr     cpsr_cxsf, r2
    ldr     lr, [r12, #CTX_LR]
    ldmia   r12, {r0-r12}                  // r0..r12 depuis le contexte
    bx      lr

    /* ---------- RESTORE USER (tâche user suspendue) ---------- */
__restore_to_user:
    ldr     sp, [r12, #CTX_SVC_SP_TOP]
    /* 1) SPSR <- usr_cpsr (forcer ARM, T=0) */
    //push {r0-r3, lr}
    //mov r0, r12
    //bl debug_print_sp
    //pop {r0-r3, lr}

    ldr     r2, [r12, #CTX_USR_CPSR]
    bic     r2, r2, #0x20
    msr     spsr_cxsf, r2

    /* 2) Registres bankés (SP/LR user) */
    cps     #0x1F
    ldr     sp, [r12, #CTX_USR_SP]
    ldr     lr, [r12, #CTX_USR_LR]
    bic     lr, lr, #1
    cps     #0x13

    /* 3) r0..r10 depuis usr_r[], garder r12 comme base ctx */
    add     r10, r12, #CTX_USR_R0
    ldmia   r10, {r0-r9}
    ldr     r10, [r12, #CTX_USR_R10]

    /* 4) LR_svc = usr_pc (pair en ARM) */
    ldr     lr, [r12, #CTX_USR_LR]
    bic     lr, lr, #1

    /* 5) Restaurer r11 puis r12 à la toute fin */
    ldr     r11, [r12, #CTX_USR_R11]
    ldr     r12, [r12, #CTX_USR_R12]

    /* 6) retour user */
    movs    pc, lr

    /* ---------- PREMIÈRE EXÉCUTION : branche selon user / kernel ---------- */
__first_run_setup:
    ldr     r2, [r12, #CTX_RET_TO_USER]
    cmp     r2, #1
    beq     __first_run_user

__first_run_kernel:
    /* pile kernel de départ */
    ldr     sp, [r12, #CTX_SP]
    /* point d’entrée kernel */
    ldr     lr, [r12, #CTX_PC]
    mov     r2, #0
    str     r2, [r12, #CTX_FIRST]
    /* r0..r12 init */
    ldmia   r12, {r0-r12}
    bx      lr

__first_run_user:
    /* pile kernel pour la tâche */
    ldr     sp, [r12, #CTX_SVC_SP_TOP]
    //ldr     sp, [r12, #CTX_SVC_SP]

    /* SPSR = usr_cpsr (ARM) */
    ldr     r2, [r12, #CTX_USR_CPSR]
    bic     r2, r2, #0x20
    msr     spsr_cxsf, r2

    /* LR_svc = usr_pc (pair) */
    ldr     lr, [r12, #CTX_USR_PC]
    bic     lr, lr, #1

    /* marquer non-première exécution */
    mov     r3, #0
    str     r3, [r12, #CTX_FIRST]

    /* SP/LR user init */
    cps     #0x1F
    ldr     sp, [r12, #CTX_USR_SP]
    ldr     lr, [r12, #CTX_USR_LR]
    bic     lr, lr, #1
    cps     #0x13

    /* r0..r10 init depuis usr_r[] */
    add     r10, r12, #CTX_USR_R0
    ldmia   r10, {r0-r9}
    ldr     r10, [r12, #CTX_USR_R10]

    /* restaurer r11 puis r12, puis sauter en user */
    ldr     r11, [r12, #CTX_USR_R11]
    ldr     r12, [r12, #CTX_USR_R12]
    movs    pc, lr
/* 
 * Notes d'utilisation:
 * 
 * ARCHITECTURE "NO RETURN":
 * Cette fonction ne retourne jamais vers son appelant !
 * Elle doit être utilisée ainsi:
 * 
 *   void schedule(void) {
 *       // ... sélection de la prochaine tâche ...
 *       current_task = next_task;
 *       
 *       // ATTENTION: Après cet appel, on n'exécute plus jamais
 *       // le code qui suit dans cette instance de schedule() !
 *       task_switch(old_ctx, new_ctx);
 *       
 *       // Cette ligne ne sera JAMAIS exécutée !
 *       printk("Never reached\n");
 *   }
 * 
 * SYMÉTRIE DE PILE:
 * - Pas de symétrie nécessaire car pas de retour
 * - Chaque tâche a sa propre pile cohérente
 * - La commutation restaure la pile de la tâche cible
 * 
 * 1. Pour configurer une nouvelle tâche user:
 *    - is_first_run = 1
 *    - returns_to_user = 1  
 *    - usr_pc = adresse d'entrée du programme
 *    - usr_sp = stack pointer user initial
 *    - usr_cpsr = 0x60000010 (mode USER, IRQ enabled)
 *    - usr_r[0-12] = arguments initiaux
 * 
 * 2. Pour configurer une nouvelle tâche kernel:
 *    - is_first_run = 1
 *    - returns_to_user = 0
 *    - pc = adresse de la fonction kernel  
 *    - svc_sp_top = sommet de la pile kernel allouée
 *    - r0-r12 = arguments de la fonction
 * 
 * 3. Les tâches suspendues (is_first_run = 0) sont restaurées
 *    exactement dans l'état où elles ont été sauvegardées
 */
/*
 * Informations de debug (visibles dans objdump)
 */
.section .rodata
task_switch_info:
    .ascii "ARM32 Task Switch v1.0 - Cortex-A15 Optimized\0"
    .ascii "Context size: 68 bytes\0"
    .ascii "Supports: Full context save/restore\0"


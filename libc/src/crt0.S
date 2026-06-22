/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/src/crt0.S
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

.section .text
.global _start

_start:
    /* Stack layout prepared by the kernel:
     *   sp[0]        = argc
     *   sp[1..]      = argv pointers, NULL terminated
     *   after argv   = envp pointers, NULL terminated
     */
    ldr r0, [sp]          /* argc */
    add r1, sp, #4        /* argv */
    add r2, r1, r0, lsl #2
    add r2, r2, #4        /* envp = argv + argc + NULL */
    bic sp, sp, #7        /* keep AAPCS 8-byte stack alignment for main */

    /* Appeler main(argc, argv, envp) */
    bl main
    
    /* Si main() retourne, appeler exit() */
    mov r0, r0          /* Code de retour de main dans r0 */
    bl exit             /* exit(code) */
    
    /* Ne devrait jamais atteindre ce point */
    b .

/* Point d'entrée alternatif avec arguments */
.global _start_with_args
_start_with_args:
    /* r0 = argc, r1 = argv */
    push {r0, r1}
    
    /* Appeler main(argc, argv) */
    bl main
    
    /* exit(retval) */
    bl exit
    b .

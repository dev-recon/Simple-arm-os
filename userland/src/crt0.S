/* crt0.S - Fichier de démarrage pour programmes userspace */

.section .text
.global _start

_start:
    /* Point d'entrée depuis le kernel */
    
    /* Initialiser la pile si nécessaire */
    /* (normalement déjà configurée par le kernel) */
    
    /* Appeler main() */
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
    
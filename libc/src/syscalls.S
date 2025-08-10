/* ========================================
 * System Calls Interface - User Space
 * Interface pour appeler le kernel depuis userspace
 * ARM 32-bit AAPCS - Adapté pour votre kernel
 * ======================================== */

.text
.align 4

/* ========================================
 * Syscall numbers - Correspondant à votre kernel
 * Utiliser les valeurs numériques directement pour l'assembleur
 * ======================================== */

/* ========================================
 * Macro pour définir un syscall
 * ======================================== */

.macro SYSCALL name, number
.global \name
.type \name, %function
\name:
    push {r7, lr}           /* Sauvegarder r7 et lr */
    mov r7, #\number        /* Numéro de syscall dans r7 */
    swi #0                  /* Software interrupt */
    pop {r7, lr}            /* Restaurer r7 et lr */
    bx lr                   /* Retour */
.endm

/* ========================================
 * Syscalls de base - Votre liste kernel
 * ======================================== */

/* Gestion de processus */
SYSCALL sys_exit, 1         /* __NR_exit */
SYSCALL sys_fork, 2         /* __NR_fork */
SYSCALL sys_execve, 11      /* __NR_execve */
SYSCALL sys_getpid, 20      /* __NR_getpid */
SYSCALL sys_getppid, 119    /* __NR_getppid */
SYSCALL sys_getuid, 24      /* __NR_getuid */
SYSCALL sys_getgid, 47      /* __NR_getgid */
SYSCALL sys_waitpid, 7      /* __NR_waitpid */

/* I/O et fichiers */
SYSCALL sys_read, 3         /* __NR_read */
SYSCALL sys_write, 4        /* __NR_write */
SYSCALL sys_open, 5         /* __NR_open */
SYSCALL sys_close, 6        /* __NR_close */
SYSCALL sys_lseek, 19       /* __NR_lseek */

/* Signaux */
SYSCALL sys_kill, 37        /* __NR_kill */
SYSCALL sys_signal, 48      /* __NR_signal */
SYSCALL sys_sigaction, 67   /* __NR_sigaction */
SYSCALL sys_sigreturn, 173  /* __NR_rt_sigreturn */

/* Syscall spécial de votre kernel */
SYSCALL sys_print, 121      /* __NR_print */

/* ========================================
 * Syscall générique avec paramètres
 * syscall(number, arg1, arg2, arg3, arg4, arg5)
 * ======================================== */

.global syscall
.type syscall, %function
syscall:
    push {r4-r7, lr}        /* Sauvegarder les registres */
    
    mov r7, r0              /* r0 (number) -> r7 */
    mov r0, r1              /* r1 (arg1) -> r0 */
    mov r1, r2              /* r2 (arg2) -> r1 */
    mov r2, r3              /* r3 (arg3) -> r2 */
    
    /* Arguments 4 et 5 sont sur la pile */
    ldr r3, [sp, #20]       /* arg4 depuis la pile */
    ldr r4, [sp, #24]       /* arg5 depuis la pile */
    
    swi #0                  /* Appel système */
    
    pop {r4-r7, lr}         /* Restaurer les registres */
    bx lr

/* ========================================
 * Wrappers C-compatibles avec gestion d'erreur
 * ======================================== */

.global write
.type write, %function  
write:
    push {r7, lr}
    mov r7, #4              /* SYS_WRITE */
    swi #0
    
    /* Vérifier si erreur (retour négatif) */
    cmp r0, #0
    bge write_success
    
    /* Gestion d'erreur : mettre errno et retourner -1 */
    rsb r0, r0, #0          /* r0 = -r0 (rendre positif) */
    bl __set_errno          /* Appeler __set_errno(r0) */
    mov r0, #-1             /* Retourner -1 */
    
write_success:
    pop {r7, lr}
    bx lr

.global read
.type read, %function
read:
    push {r7, lr}
    mov r7, #3              /* SYS_READ */
    swi #0
    
    cmp r0, #0
    bge read_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
read_success:
    pop {r7, lr}
    bx lr

.global open
.type open, %function
open:
    push {r7, lr}
    mov r7, #5              /* SYS_OPEN */
    swi #0
    
    cmp r0, #0
    bge open_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
open_success:
    pop {r7, lr}
    bx lr

.global close
.type close, %function
close:
    push {r7, lr}
    mov r7, #6              /* SYS_CLOSE */
    swi #0
    
    cmp r0, #0
    bge close_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
close_success:
    pop {r7, lr}
    bx lr

.global exit
.type exit, %function
exit:
    mov r7, #1              /* SYS_EXIT */
    swi #0
    /* Ne retourne jamais */
    b .

.global _exit
.type _exit, %function
_exit:
    mov r7, #1              /* Alias pour exit */
    swi #0
    b .

.global getpid
.type getpid, %function
getpid:
    push {r7, lr}
    mov r7, #20             /* SYS_GETPID */
    swi #0
    pop {r7, lr}
    bx lr

.global getppid  
.type getppid, %function
getppid:
    push {r7, lr}
    mov r7, #119            /* SYS_GETPPID */
    swi #0
    pop {r7, lr}
    bx lr

.global getuid
.type getuid, %function
getuid:
    push {r7, lr}
    mov r7, #24             /* SYS_GETUID */
    swi #0
    pop {r7, lr}
    bx lr

.global getgid
.type getgid, %function
getgid:
    push {r7, lr}
    mov r7, #47             /* SYS_GETGID */
    swi #0
    pop {r7, lr}
    bx lr

.global fork
.type fork, %function
fork:
    push {r7, lr}
    mov r7, #2              /* SYS_FORK */
    swi #0
    
    /* fork retourne 0 pour l'enfant, PID pour le parent, -1 pour erreur */
    cmp r0, #0
    bge fork_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
fork_success:
    pop {r7, lr}
    bx lr

.global execve
.type execve, %function
execve:
    push {r7, lr}
    mov r7, #11             /* SYS_EXECVE */
    swi #0
    
    /* execve ne retourne qu'en cas d'erreur */
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
    pop {r7, lr}
    bx lr

.global waitpid
.type waitpid, %function
waitpid:
    push {r7, lr}
    mov r7, #7              /* SYS_WAITPID */
    swi #0
    
    cmp r0, #0
    bge waitpid_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
waitpid_success:
    pop {r7, lr}
    bx lr

.global kill
.type kill, %function
kill:
    push {r7, lr}
    mov r7, #37             /* SYS_KILL */
    swi #0
    
    cmp r0, #0
    bge kill_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
kill_success:
    pop {r7, lr}
    bx lr

.global signal
.type signal, %function
signal:
    push {r7, lr}
    mov r7, #48             /* SYS_SIGNAL */
    swi #0
    pop {r7, lr}
    bx lr

.global sigaction
.type sigaction, %function
sigaction:
    push {r7, lr}
    mov r7, #67             /* SYS_SIGACTION */
    swi #0
    
    cmp r0, #0
    bge sigaction_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
sigaction_success:
    pop {r7, lr}
    bx lr

.global lseek
.type lseek, %function
lseek:
    push {r7, lr}
    mov r7, #19             /* SYS_LSEEK */
    swi #0
    
    cmp r0, #0
    bge lseek_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
lseek_success:
    pop {r7, lr}
    bx lr

/* Syscall spécial de votre kernel */
.global print
.type print, %function
print:
    push {r7, lr}
    mov r7, #121            /* SYS_PRINT */
    swi #0
    pop {r7, lr}
    bx lr

/* ========================================
 * Gestion d'errno (simple)
 * ======================================== */

.data
.global errno
errno:
    .word 0

.text
.global __set_errno
.type __set_errno, %function
__set_errno:
    ldr r1, =errno
    str r0, [r1]
    bx lr

.global __errno_location
.type __errno_location, %function
__errno_location:
    ldr r0, =errno
    bx lr

/* ========================================
 * Fonctions utilitaires
 * ======================================== */

/* Version alternative de exit pour compatibilité */
.global abort
.type abort, %function
abort:
    mov r0, #1              /* Code de sortie d'erreur */
    mov r7, #1
    swi #0
    b .

/* ========================================
 * Fin du fichier
 * ======================================== */

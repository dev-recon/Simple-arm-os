/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/src/syscalls.S
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

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
SYSCALL sys_setpgid, 57     /* __NR_setpgid */
SYSCALL sys_getpgrp, 65     /* __NR_getpgrp */
SYSCALL sys_stty, 31        /* __NR_stty */
SYSCALL sys_gtty, 32        /* __NR_gtty */
SYSCALL sys_waitpid, 7      /* __NR_waitpid */
SYSCALL sys_brk, 45         /* __NR_brk */



/* I/O et fichiers */
SYSCALL sys_read, 3         /* __NR_read */
SYSCALL sys_write, 4        /* __NR_write */
SYSCALL sys_open, 5         /* __NR_open */
SYSCALL sys_creat, 8        /* __NR_creat */
SYSCALL sys_close, 6        /* __NR_close */
SYSCALL sys_link, 9         /* __NR_link */
SYSCALL sys_lseek, 19       /* __NR_lseek */
SYSCALL sys_time, 13        /* __NR_time */
SYSCALL sys_rename, 38      /* __NR_rename */
SYSCALL sys_mkdir, 39       /* __NR_mkdir */
SYSCALL sys_rmdir, 40       /* __NR_rmdir */
SYSCALL sys_unlink, 10      /* __NR_unlink */
SYSCALL sys_symlink, 83     /* __NR_symlink */
SYSCALL sys_readlink, 85    /* __NR_readlink */
SYSCALL sys_chdir, 12       /* __NR_chdir */
SYSCALL sys_access, 33      /* __NR_access */
SYSCALL sys_umask, 60       /* __NR_umask */
SYSCALL sys_chmod, 15       /* __NR_chmod */
SYSCALL sys_chown, 16       /* __NR_chown / __NR_lchown */
SYSCALL sys_ioctl, 54       /* __NR_ioctl */
SYSCALL sys_fcntl, 55       /* __NR_fcntl */

SYSCALL sys_dup, 41         /* __NR_dup2 */
SYSCALL sys_dup2, 63        /* __NR_dup2 */
SYSCALL sys_getcwd, 183     /* __NR_getcwd */

SYSCALL sys_pipe, 42        /* __NR_pipe */
SYSCALL sys_stat, 106       /* __NR_stat */
SYSCALL sys_lstat, 107      /* __NR_lstat */
SYSCALL sys_fstat, 108      /* __NR_fstat */
SYSCALL sys_getdents, 141   /* __NR_getdents */
SYSCALL sys_gettimeofday, 78 /* __NR_gettimeofday */


/* Signaux */
SYSCALL sys_kill, 37        /* __NR_kill */
SYSCALL sys_signal, 48      /* __NR_signal */
SYSCALL sys_sigaction, 67   /* __NR_sigaction */
SYSCALL sys_sigreturn, 173  /* __NR_rt_sigreturn */
SYSCALL sys_nanosleep, 162  /* __NR_nanosleep */
SYSCALL sys_sysinfo,   116  /* __NR_sysinfo — getprocs temporaire */


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

//   READ -> SYS_WRITE
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

//   READ -> SYS_READ
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

//   OPEN -> SYS_OPEN
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

.global creat
.type creat, %function
creat:
    push {r7, lr}
    mov r7, #8              /* SYS_CREAT */
    swi #0

    cmp r0, #0
    bge creat_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

creat_success:
    pop {r7, lr}
    bx lr

//   CLOSE -> SYS_CLOSE
.global open
.global close
.type close, %function
close:
    push {r0, r1, r7, lr}
    bl pflush
    pop {r0, r1, r7, lr}
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

//   EXIT -> SYS_EXIT
.global exit
.type exit, %function
exit:
    push {r0, r1, r7, lr}
    bl pflush
    pop {r0, r1, r7, lr}
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

//   GETPID -> SYS_GETPID
.global getpid
.type getpid, %function
getpid:
    push {r7, lr}
    mov r7, #20             /* SYS_GETPID */
    swi #0
    pop {r7, lr}
    bx lr

//   GETPPID -> SYS_GETPPID
.global getppid  
.type getppid, %function
getppid:
    push {r7, lr}
    mov r7, #119            /* SYS_GETPPID */
    swi #0
    pop {r7, lr}
    bx lr

//   GETUID -> SYS_GETUID
.global getuid
.type getuid, %function
getuid:
    push {r7, lr}
    mov r7, #24             /* SYS_GETUID */
    swi #0
    pop {r7, lr}
    bx lr

//   GETGID -> SYS_GETGID
.global getgid
.type getgid, %function
getgid:
    push {r7, lr}
    mov r7, #47             /* SYS_GETGID */
    swi #0
    pop {r7, lr}
    bx lr

//   SETPGID -> SYS_SETPGID
.global setpgid
.type setpgid, %function
setpgid:
    push {r7, lr}
    mov r7, #57             /* SYS_SETPGID */
    swi #0

    cmp r0, #0
    bge setpgid_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

setpgid_success:
    pop {r7, lr}
    bx lr

//   GETPGRP -> SYS_GETPGRP
.global getpgrp
.type getpgrp, %function
getpgrp:
    push {r7, lr}
    mov r7, #65             /* SYS_GETPGRP */
    swi #0

    cmp r0, #0
    bge getpgrp_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

getpgrp_success:
    pop {r7, lr}
    bx lr

//   STTY -> SYS_STTY
.global stty
.type stty, %function
stty:
    push {r7, lr}
    mov r7, #31             /* SYS_STTY */
    swi #0

    cmp r0, #0
    bge stty_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

stty_success:
    pop {r7, lr}
    bx lr

//   GTTY -> SYS_GTTY
.global gtty
.type gtty, %function
gtty:
    push {r7, lr}
    mov r7, #32             /* SYS_GTTY */
    swi #0

    cmp r0, #0
    bge gtty_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

gtty_success:
    pop {r7, lr}
    bx lr

//   TCSETPGRP -> SYS_STTY(TTY_STTY_SET_FOREGROUND_PGID_FD, fd, pgrp)
.global tcsetpgrp
.type tcsetpgrp, %function
tcsetpgrp:
    push {r7, lr}
    mov r2, r1              /* pgrp */
    mov r1, r0              /* fd */
    mov r0, #2              /* TTY_STTY_SET_FOREGROUND_PGID_FD */
    mov r7, #31             /* SYS_STTY */
    swi #0

    cmp r0, #0
    bge tcsetpgrp_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

tcsetpgrp_success:
    pop {r7, lr}
    bx lr

//   TCGETPGRP -> SYS_GTTY(TTY_GTTY_GET_FOREGROUND_PGID_FD, fd)
.global tcgetpgrp
.type tcgetpgrp, %function
tcgetpgrp:
    push {r7, lr}
    mov r1, r0              /* fd */
    mov r0, #2              /* TTY_GTTY_GET_FOREGROUND_PGID_FD */
    mov r7, #32             /* SYS_GTTY */
    swi #0

    cmp r0, #0
    bge tcgetpgrp_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

tcgetpgrp_success:
    pop {r7, lr}
    bx lr

//   FORK -> SYS_FORK
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

//   EXECVE -> SYS_EXECVE
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

//   WAITPID -> SYS_WAITPID
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

//   KILL -> SYS_KILL
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

//   SIGNAL -> SYS_SIGNAL
.global signal
.type signal, %function
signal:
    push {r4, r5, r7, lr}
    mov r4, r0              /* sig */
    mov r5, r1              /* handler */
    sub sp, sp, #32         /* nouvelle action + ancienne action */

    str r5, [sp, #0]
    mov r2, #0
    str r2, [sp, #4]        /* sa_mask */
    mov r2, #1
    str r2, [sp, #8]        /* SA_RESTART */
    ldr r2, =__signal_return_trampoline
    str r2, [sp, #12]

    mov r0, r4
    mov r1, sp
    add r2, sp, #16
    mov r7, #67             /* __NR_sigaction */
    swi #0

    cmp r0, #0
    ldrge r0, [sp, #16]     /* ancien handler */
    add sp, sp, #32
    pop {r4, r5, r7, lr}
    bx lr

//   SIGACTION -> SYS_SIGACTION
.global sigaction
.type sigaction, %function
sigaction:
    push {r7, lr}
    cmp r1, #0
    ldrne r3, =__signal_return_trampoline
    strne r3, [r1, #12]
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

.global __signal_return_trampoline
.type __signal_return_trampoline, %function
__signal_return_trampoline:
    mov r7, #173            /* __NR_rt_sigreturn */
    swi #0
    mov r7, #1              /* sys_exit si sigreturn echoue */
    mov r0, #-1
    swi #0

//   LSEEK -> SYS_LSEEK
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

//   PRINT -> SYS_PRINT
/* Syscall spécial de votre kernel */
.global print
.type print, %function
print:
    push {r7, lr}
    mov r7, #121            /* SYS_PRINT */
    swi #0
    pop {r7, lr}
    bx lr


/* Dans la section des wrappers C-compatibles */
//   BRK -> SYS_BRK
.global brk
.type brk, %function
brk:
    push {r7, lr}
    mov r7, #45             // SYS_BRK 
    swi #0
    
    cmp r0, #0
    bge brk_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
brk_success:
    pop {r7, lr}
    bx lr

//   SBRK -> utilise BRK
.global sbrk
.type sbrk, %function
sbrk:
    push {r4-r7, lr}
    
    /* Appeler sys_brk avec le nouveau brk */
    mov r7, #45
    swi #0
    
    cmp r0, #0
    bge sbrk_success
    
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

    
sbrk_error:
    mov r0, #12             /* ENOMEM */
    bl __set_errno
    mov r0, #-1
    
sbrk_success:
    pop {r4-r7, lr}
    bx lr


.global mkdir
.type mkdir, %function
mkdir:
    push {r7, lr}
    mov r7, #39             /* SYS_MKDIR */
    swi #0
    
    cmp r0, #0
    bge mkdir_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
mkdir_success:
    pop {r7, lr}
    bx lr

.global rename
.type rename, %function
rename:
    push {r7, lr}
    mov r7, #38             /* SYS_RENAME */
    swi #0

    cmp r0, #0
    bge rename_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

rename_success:
    pop {r7, lr}
    bx lr

.global rmdir
.type rmdir, %function
rmdir:
    push {r7, lr}
    mov r7, #40             /* SYS_RMDIR */
    swi #0
    
    cmp r0, #0
    bge rmdir_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
rmdir_success:
    pop {r7, lr}
    bx lr


.global chdir
.type chdir, %function
chdir:
    push {r7, lr}
    mov r7, #12             /* SYS_CHDIR */
    swi #0
    
    cmp r0, #0
    bge chdir_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
chdir_success:
    pop {r7, lr}
    bx lr


.global unlink
.type unlink, %function
unlink:
    push {r7, lr}
    mov r7, #10             /* SYS_UNLINK */
    swi #0
    
    cmp r0, #0
    bge unlink_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
unlink_success:
    pop {r7, lr}
    bx lr

.global access
.type access, %function
access:
    push {r7, lr}
    mov r7, #33             /* SYS_ACCESS */
    swi #0

    cmp r0, #0
    bge access_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

access_success:
    pop {r7, lr}
    bx lr

.global umask
.type umask, %function
umask:
    push {r7, lr}
    mov r7, #60             /* SYS_UMASK */
    swi #0
    pop {r7, lr}
    bx lr

.global chmod
.type chmod, %function
chmod:
    push {r7, lr}
    mov r7, #15             /* SYS_CHMOD */
    swi #0

    cmp r0, #0
    bge chmod_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

chmod_success:
    pop {r7, lr}
    bx lr

.global chown
.type chown, %function
chown:
    push {r7, lr}
    mov r7, #16             /* SYS_CHOWN / SYS_LCHOWN */
    swi #0

    cmp r0, #0
    bge chown_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

chown_success:
    pop {r7, lr}
    bx lr

.global fcntl
.type fcntl, %function
fcntl:
    push {r7, lr}
    mov r7, #55             /* SYS_FCNTL */
    swi #0

    cmp r0, #0
    bge fcntl_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

fcntl_success:
    pop {r7, lr}
    bx lr

.global ioctl
.type ioctl, %function
ioctl:
    push {r7, lr}
    mov r7, #54             /* SYS_IOCTL */
    swi #0

    cmp r0, #0
    bge ioctl_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

ioctl_success:
    pop {r7, lr}
    bx lr

.global dup
.type dup, %function
dup:
    push {r0, r1, r7, lr}
    bl pflush
    pop {r0, r1, r7, lr}
    push {r7, lr}
    mov r7, #41            /* SYS_DUP */
    swi #0
    
    cmp r0, #0
    bge dup_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
dup_success:
    pop {r7, lr}
    bx lr


.global dup2
.type dup2, %function
dup2:
    push {r0, r1, r7, lr}
    bl pflush
    pop {r0, r1, r7, lr}
    push {r7, lr}
    mov r7, #63             /* SYS_DUP2 */
    swi #0
    
    cmp r0, #0
    bge dup2_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
dup2_success:
    pop {r7, lr}
    bx lr

.global _getcwd
.type _getcwd, %function
_getcwd:
    push {r7, lr}
    mov r7, #183            /* SYS_GETCWD */
    swi #0
    
    cmp r0, #0
    bge _getcwd_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #0              /* getcwd retourne NULL en cas d'erreur */
    
_getcwd_success:
    pop {r7, lr}
    bx lr


.global pipe
.type pipe, %function
pipe:
    push {r7, lr}
    mov r7, #42             /* SYS_PIPE */
    swi #0
    
    cmp r0, #0
    bge pipe_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
pipe_success:
    pop {r7, lr}
    bx lr


.global stat
.type stat, %function
stat:
    push {r7, lr}
    mov r7, #106            /* SYS_STAT */
    swi #0
    
    cmp r0, #0
    bge stat_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
stat_success:
    pop {r7, lr}
    bx lr

.global lstat
.type lstat, %function
lstat:
    push {r7, lr}
    mov r7, #107            /* SYS_LSTAT */
    swi #0

    cmp r0, #0
    bge lstat_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

lstat_success:
    pop {r7, lr}
    bx lr

.global fstat
.type fstat, %function
fstat:
    push {r7, lr}
    mov r7, #108            /* SYS_FSTAT */
    swi #0
    
    cmp r0, #0
    bge fstat_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
    
fstat_success:
    pop {r7, lr}
    bx lr

.global getdents
.type getdents, %function
getdents:
    push {r7, lr}
    mov r7, #141        /* __NR_getdents */
    swi #0
    pop {r7, lr}
    bx lr

.global getsysinfo
.type getsysinfo, %function
getsysinfo:
    push {r7, lr}
    mov r7, #116            /* __NR_sysinfo */
    swi #0
    cmp r0, #0
    bge getsysinfo_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
getsysinfo_success:
    pop {r7, lr}
    bx lr

.global nanosleep
.type nanosleep, %function
nanosleep:
    push {r7, lr}
    mov r7, #162        /* __NR_nanosleep */
    swi #0

    cmp r0, #0
    bge nanosleep_success

    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

nanosleep_success:
    pop {r7, lr}
    bx lr

.global time
.type time, %function
time:
    push {r7, lr}
    mov r7, #13             /* SYS_TIME */
    swi #0

    cmp r0, #0
    bge time_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

time_success:
    pop {r7, lr}
    bx lr

.global gettimeofday
.type gettimeofday, %function
gettimeofday:
    push {r7, lr}
    mov r7, #78             /* SYS_GETTIMEOFDAY */
    swi #0

    cmp r0, #0
    bge gettimeofday_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

gettimeofday_success:
    pop {r7, lr}
    bx lr

.global link
.type link, %function
link:
    push {r7, lr}
    mov r7, #9              /* SYS_LINK */
    swi #0

    cmp r0, #0
    bge link_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

link_success:
    pop {r7, lr}
    bx lr

.global symlink
.type symlink, %function
symlink:
    push {r7, lr}
    mov r7, #83             /* SYS_SYMLINK */
    swi #0

    cmp r0, #0
    bge symlink_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

symlink_success:
    pop {r7, lr}
    bx lr

.global readlink
.type readlink, %function
readlink:
    push {r7, lr}
    mov r7, #85             /* SYS_READLINK */
    swi #0

    cmp r0, #0
    bge readlink_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1

readlink_success:
    pop {r7, lr}
    bx lr

.global shm_open
.type shm_open, %function
shm_open:
    push {r7, lr}
    mov r7, #190        /* __NR_shm_open */
    swi #0
    cmp r0, #0
    bge shm_open_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
shm_open_success:
    pop {r7, lr}
    bx lr

.global shm_unlink
.type shm_unlink, %function
shm_unlink:
    push {r7, lr}
    mov r7, #191        /* __NR_shm_unlink */
    swi #0
    cmp r0, #0
    bge shm_unlink_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
shm_unlink_success:
    pop {r7, lr}
    bx lr

.global shm_map
.type shm_map, %function
shm_map:
    push {r7, lr}
    mov r7, #192        /* __NR_shm_map */
    swi #0
    cmp r0, #0
    bge shm_map_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #0
shm_map_success:
    pop {r7, lr}
    bx lr

.global shm_unmap
.type shm_unmap, %function
shm_unmap:
    push {r7, lr}
    mov r7, #193        /* __NR_shm_unmap */
    swi #0
    cmp r0, #0
    bge shm_unmap_success
    rsb r0, r0, #0
    bl __set_errno
    mov r0, #-1
shm_unmap_success:
    pop {r7, lr}
    bx lr

.global sys_shutdown
.type sys_shutdown, %function
sys_shutdown:
    push {r7, lr}
    mov r7, #194        /* __NR_shutdown */
    swi #0
    pop {r7, lr}
    bx lr

/* ========================================
 * Gestion d'errno (simple)
 * ======================================== */

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

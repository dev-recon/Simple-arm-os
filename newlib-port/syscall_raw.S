/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: newlib-port/syscall_raw.S
 * Layer: Userland / newlib port
 * Description: Newlib syscall glue and ArmOS ABI adaptation layer.
 */

.text
.align 4

.macro RAW_SYSCALL name, number
.global \name
.type \name, %function
\name:
    push {r7, lr}
    mov r7, #\number
    swi #0
    pop {r7, lr}
    bx lr
.endm

.macro RAW_SYSCALL5 name, number
.global \name
.type \name, %function
\name:
    /*
     * AAPCS passes the 5th C argument on the user stack. The ArmOS SVC entry
     * expects arg5 in user r4, so wrappers with five syscall arguments must
     * marshal it explicitly while preserving callee-saved r4.
     */
    push {r4, r5, r7, lr}
    ldr r4, [sp, #16]
    mov r7, #\number
    swi #0
    pop {r4, r5, r7, lr}
    bx lr
.endm

RAW_SYSCALL sys_exit, 1
RAW_SYSCALL sys_fork, 2
RAW_SYSCALL sys_read, 3
RAW_SYSCALL sys_write, 4
RAW_SYSCALL sys_open, 5
RAW_SYSCALL sys_close, 6
RAW_SYSCALL sys_waitpid, 7
RAW_SYSCALL sys_creat, 8
RAW_SYSCALL sys_link, 9
RAW_SYSCALL sys_unlink, 10
RAW_SYSCALL sys_execve, 11
RAW_SYSCALL sys_chdir, 12
RAW_SYSCALL sys_time, 13
RAW_SYSCALL sys_mknod, 14
RAW_SYSCALL sys_alarm, 27
RAW_SYSCALL sys_pause, 29
RAW_SYSCALL sys_utime, 30
RAW_SYSCALL sys_mount, 21
RAW_SYSCALL sys_umount, 22
RAW_SYSCALL sys_setuid, 23
RAW_SYSCALL sys_chmod, 15
RAW_SYSCALL sys_chown, 16
RAW_SYSCALL sys_lseek, 19
RAW_SYSCALL sys_getpid, 20
RAW_SYSCALL sys_getuid, 24
RAW_SYSCALL sys_geteuid, 49
RAW_SYSCALL sys_access, 33
RAW_SYSCALL sys_nice, 34
RAW_SYSCALL sys_sync, 36
RAW_SYSCALL sys_kill, 37
RAW_SYSCALL sys_rename, 38
RAW_SYSCALL sys_mkdir, 39
RAW_SYSCALL sys_rmdir, 40
RAW_SYSCALL sys_dup, 41
RAW_SYSCALL sys_pipe, 42
RAW_SYSCALL sys_times, 43
RAW_SYSCALL sys_brk, 45
RAW_SYSCALL sys_stty, 31
RAW_SYSCALL sys_gtty, 32
RAW_SYSCALL sys_ioctl, 54
RAW_SYSCALL sys_fcntl, 55
RAW_SYSCALL sys_setpgid, 57
RAW_SYSCALL sys_setgid, 46
RAW_SYSCALL sys_getgid, 47
RAW_SYSCALL sys_getegid, 50
RAW_SYSCALL sys_umask, 60
RAW_SYSCALL sys_dup2, 63
RAW_SYSCALL sys_getpgrp, 65
RAW_SYSCALL sys_setsid, 66
RAW_SYSCALL sys_sigaction, 67
RAW_SYSCALL sys_sigsuspend, 72
RAW_SYSCALL sys_sigpending, 73
RAW_SYSCALL sys_getrusage, 77
RAW_SYSCALL sys_gettimeofday, 78
RAW_SYSCALL sys_symlink, 83
RAW_SYSCALL sys_readlink, 85
RAW_SYSCALL sys_truncate, 92
RAW_SYSCALL sys_ftruncate, 93
RAW_SYSCALL sys_getpriority, 96
RAW_SYSCALL sys_setpriority, 97
RAW_SYSCALL sys_statfs, 99
RAW_SYSCALL sys_fsync, 118
RAW_SYSCALL sys_stat, 106
RAW_SYSCALL sys_lstat, 107
RAW_SYSCALL sys_fstat, 108
RAW_SYSCALL sys_wait4, 114
RAW_SYSCALL sys_sysinfo, 116
RAW_SYSCALL sys_getppid, 119
RAW_SYSCALL sys_uname, 122
RAW_SYSCALL sys_mprotect, 125
RAW_SYSCALL sys_sigprocmask, 126
RAW_SYSCALL sys_getdents, 141
RAW_SYSCALL5 sys_select, 142
RAW_SYSCALL sys_readv, 145
RAW_SYSCALL sys_writev, 146
RAW_SYSCALL sys_getsid, 147
RAW_SYSCALL sys_nanosleep, 162
RAW_SYSCALL sys_poll, 168
RAW_SYSCALL sys_getcwd, 183
RAW_SYSCALL sys_shm_open, 190
RAW_SYSCALL sys_shm_unlink, 191
RAW_SYSCALL sys_shm_map, 192
RAW_SYSCALL sys_shm_unmap, 193
RAW_SYSCALL sys_shutdown, 194
RAW_SYSCALL5 sys_mmap, 195
RAW_SYSCALL sys_munmap, 196
RAW_SYSCALL sys_socket, 281
RAW_SYSCALL sys_bind, 282
RAW_SYSCALL sys_connect, 283
RAW_SYSCALL sys_listen, 284
RAW_SYSCALL sys_accept, 285

.global __signal_return_trampoline
.type __signal_return_trampoline, %function
__signal_return_trampoline:
    mov r7, #173
    swi #0
    mov r7, #1
    mov r0, #-1
    swi #0

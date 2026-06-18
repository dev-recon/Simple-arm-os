/* syscall_raw.S - raw ARM EABI syscall wrappers for newlib glue.
 *
 * These wrappers intentionally return the kernel raw value. Negative errors
 * are converted to errno by newlib-port/syscalls.c.
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
RAW_SYSCALL sys_mount, 21
RAW_SYSCALL sys_umount, 22
RAW_SYSCALL sys_chmod, 15
RAW_SYSCALL sys_chown, 16
RAW_SYSCALL sys_lseek, 19
RAW_SYSCALL sys_getpid, 20
RAW_SYSCALL sys_getuid, 24
RAW_SYSCALL sys_access, 33
RAW_SYSCALL sys_sync, 36
RAW_SYSCALL sys_kill, 37
RAW_SYSCALL sys_rename, 38
RAW_SYSCALL sys_mkdir, 39
RAW_SYSCALL sys_rmdir, 40
RAW_SYSCALL sys_dup, 41
RAW_SYSCALL sys_pipe, 42
RAW_SYSCALL sys_brk, 45
RAW_SYSCALL sys_stty, 31
RAW_SYSCALL sys_gtty, 32
RAW_SYSCALL sys_ioctl, 54
RAW_SYSCALL sys_fcntl, 55
RAW_SYSCALL sys_setpgid, 57
RAW_SYSCALL sys_getgid, 47
RAW_SYSCALL sys_umask, 60
RAW_SYSCALL sys_dup2, 63
RAW_SYSCALL sys_getpgrp, 65
RAW_SYSCALL sys_sigaction, 67
RAW_SYSCALL sys_gettimeofday, 78
RAW_SYSCALL sys_symlink, 83
RAW_SYSCALL sys_readlink, 85
RAW_SYSCALL sys_ftruncate, 93
RAW_SYSCALL sys_statfs, 99
RAW_SYSCALL sys_stat, 106
RAW_SYSCALL sys_lstat, 107
RAW_SYSCALL sys_fstat, 108
RAW_SYSCALL sys_sysinfo, 116
RAW_SYSCALL sys_getppid, 119
RAW_SYSCALL sys_getdents, 141
RAW_SYSCALL sys_nanosleep, 162
RAW_SYSCALL sys_getcwd, 183
RAW_SYSCALL sys_shm_open, 190
RAW_SYSCALL sys_shm_unlink, 191
RAW_SYSCALL sys_shm_map, 192
RAW_SYSCALL sys_shm_unmap, 193
RAW_SYSCALL sys_shutdown, 194

.global __signal_return_trampoline
.type __signal_return_trampoline, %function
__signal_return_trampoline:
    mov r7, #173
    swi #0
    mov r7, #1
    mov r0, #-1
    swi #0

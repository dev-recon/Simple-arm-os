/* include/kernel/syscalls.h */
#ifndef _KERNEL_SYSCALLS_H
#define _KERNEL_SYSCALLS_H

#include <kernel/types.h>
#include <kernel/vfs.h>
#include <kernel/signal.h>  /* Pour sig_handler_t et sigaction_t */

/* Forward declarations */
struct process;

/* Syscall numbers (Linux ARM32 compatible) */
#define __NR_restart_syscall      0
#define __NR_exit                 1
#define __NR_fork                 2
#define __NR_read                 3
#define __NR_write                4
#define __NR_open                 5
#define __NR_close                6
#define __NR_waitpid              7
#define __NR_creat                8
#define __NR_link                 9
#define __NR_unlink              10
#define __NR_execve              11
#define __NR_chdir               12
#define __NR_time                13
#define __NR_mknod               14
#define __NR_chmod               15
#define __NR_lchown              16
#define __NR_break               17
#define __NR_oldstat             18
#define __NR_lseek               19
#define __NR_getpid              20
#define __NR_mount               21
#define __NR_umount              22
#define __NR_setuid              23
#define __NR_getuid              24
#define __NR_stime               25
#define __NR_ptrace              26
#define __NR_alarm               27
#define __NR_oldfstat            28
#define __NR_pause               29
#define __NR_utime               30
#define __NR_stty                31
#define __NR_gtty                32
#define __NR_access              33
#define __NR_nice                34
#define __NR_ftime               35
#define __NR_sync                36
#define __NR_kill                37
#define __NR_rename              38
#define __NR_mkdir               39
#define __NR_rmdir               40
#define __NR_dup                 41
#define __NR_pipe                42
#define __NR_times               43
#define __NR_prof                44
#define __NR_brk                 45
#define __NR_setgid              46
#define __NR_getgid              47
#define __NR_signal              48
#define __NR_geteuid             49
#define __NR_getegid             50
#define __NR_sigaction           67
#define __NR_getppid            119  /* Moved to avoid conflicts */
#define __NR_print              121
#define __NR_rt_sigreturn       173

/* Syscall handler */
int syscall_handler(uint32_t syscall_num, uint32_t arg1, uint32_t arg2, 
                   uint32_t arg3, uint32_t arg4, uint32_t arg5);

/* File syscalls */
int sys_read(int fd, void* buf, size_t count);
int sys_write(int fd, const void* buf, size_t count);
int sys_open(const char* pathname, int flags, mode_t mode);
int sys_close(int fd);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_stat(const char* pathname, struct stat* statbuf);
int sys_print(const char* msg);

/* Process syscalls */
int sys_fork(void);
int sys_execve(const char* filename, char* const argv[], char* const envp[]);
void sys_exit(int status);
int sys_waitpid(pid_t pid, int* status, int options);
int kernel_waitpid(pid_t pid, int* status, int options);

/* Process info syscalls */
int sys_getpid(void);
int sys_getppid(void);
int sys_getuid(void);
int sys_getgid(void);

/* Signal syscalls */
int sys_kill(pid_t pid, int sig);
int sys_signal(int sig, sig_handler_t handler);
int sys_sigaction(int sig, const sigaction_t* act, sigaction_t* oldact);
void sys_sigreturn(void);

/* Memory syscalls */
int sys_brk(void* addr);

/* Additional process syscalls */
int sys_dup(int oldfd);
int sys_dup2(int oldfd, int newfd);
int sys_pipe(int pipefd[2]);
int sys_chdir(const char* path);
int sys_getcwd(char* buf, size_t size);

#endif
/* include/kernel/syscalls.h */
#ifndef _KERNEL_SYSCALLS_H
#define _KERNEL_SYSCALLS_H

#include <kernel/types.h>
#include <kernel/vfs.h>
#include <kernel/signal.h>  /* Pour sig_handler_t et sigaction_t */
#include <kernel/dirent.h>

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
#define __NR_chown               __NR_lchown
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
#define __NR_ioctl               54
#define __NR_fcntl               55
#define __NR_setpgid             57
#define __NR_umask               60
#define __NR_dup2                63      /* dup2 */
#define __NR_getpgrp             65
#define __NR_sigaction           67
#define __NR_gettimeofday        78
#define __NR_symlink             83
#define __NR_readlink            85
#define __NR_ftruncate           93
#define __NR_stat               106
#define __NR_lstat              107
#define __NR_fstat              108
#define __NR_getppid            119  /* Moved to avoid conflicts */
#define __NR_print              121
#define __NR_getdents           141
#define __NR_nanosleep          162
#define __NR_rt_sigreturn       173
#define __NR_getcwd             183     /* getcwd */
#define __NR_shm_open           190
#define __NR_shm_unlink         191
#define __NR_shm_map            192
#define __NR_shm_unmap          193
#define __NR_shutdown           194
#define __NR_sysinfo            116     /* reused for getprocs — remplacer par /proc plus tard */

/* Informations sur un processus */
struct proc_info {
    uint32_t tid;
    int      pid;
    int      ppid;
    int      sid;
    int      tty;
    uint32_t uid;
    uint32_t gid;
    uint32_t priority;
    uint32_t switches;
    uint32_t cpu_pct_x10;   /* %CPU * 10  (ex: 875 = 87.5%) */
    uint32_t stack_kb;
    uint32_t heap_kb;
    uint32_t vm_kb;
    uint32_t rss_kb;
    uint32_t l2_tables;
    uint32_t page_faults;
    uint32_t cow_faults;
    uint32_t stack_faults;
    char     name[32];
    char     state;          /* R=run S=sleep Z=zombie T=term D=uninterruptible */
    char     type;           /* P=process K=kernel T=thread */
    char     _pad[2];
};

/* Réponse complète de sys_sysinfo */
struct sysinfo_response {
    uint32_t        mem_total_kb;
    uint32_t        mem_free_kb;
    int             proc_count;
    uint32_t        _pad;
    uint32_t        tasks_created;
    uint32_t        tasks_destroyed;
    uint32_t        zombies_created;
    uint32_t        zombies_reaped;
    uint32_t        failed_forks;
    uint32_t        scheduler_refused;
    uint32_t        ready_queue_refused;
    uint32_t        stack_pages_allocated;
    uint32_t        stack_pages_freed;
    uint32_t        phys_pages_allocated;
    uint32_t        phys_pages_freed;
    uint32_t        asid_rollovers;
    uint32_t        state_sync_repairs;
    uint32_t        blocked_signal_wakeups;
    uint32_t        tty_stale_waiters;
    uint32_t        uninterruptible_timeouts;
    struct proc_info procs[64];
};

struct timeval {
    time_t tv_sec;
    uint32_t tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

/* Syscall handler */
int syscall_handler(uint32_t syscall_num, uint32_t arg1, uint32_t arg2, 
                   uint32_t arg3, uint32_t arg4, uint32_t arg5);

/* File syscalls */
int sys_read(int fd, void* buf, size_t count);
int sys_write(int fd, const void* buf, size_t count);
int sys_open(const char* pathname, int flags, mode_t mode);
int sys_creat(const char* pathname, mode_t mode);
int sys_close(int fd);
int sys_fcntl(int fd, int cmd, uint32_t arg);
int sys_ioctl(int fd, uint32_t request, uint32_t arg);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_stat(const char* pathname, struct stat* statbuf);
int sys_lstat(const char* pathname, struct stat* statbuf);
int sys_fstat(int fd, struct stat* statbuf);
int sys_ftruncate(int fd, off_t length);
int sys_print(const char* msg);
int sys_mkdir(const char* pathname, mode_t mode);
int sys_rmdir(const char* pathname);
int sys_link(const char* oldpath, const char* newpath);
int sys_unlink(const char* pathname);
int sys_symlink(const char* target, const char* linkpath);
int sys_readlink(const char* pathname, char* buf, size_t bufsiz);
int sys_rename(const char* oldpath, const char* newpath);
int sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
int sys_access(const char* pathname, int mode);
int sys_umask(int mask);
int sys_chmod(const char* pathname, mode_t mode);
int sys_chown(const char* pathname, uid_t owner, gid_t group);

/* Process syscalls */
#define WNOHANG    1
#define WUNTRACED  2

int sys_fork(void);
int sys_execve(const char* filename, char* const argv[], char* const envp[]);
void sys_exit(int status);
int sys_waitpid(pid_t pid, int* status, int options);
int kernel_waitpid(pid_t pid, int* status, int options, task_t* parent);
int kernel_open(char* kernel_path, int flags, mode_t mode);
int sys_stty(int cmd, uint32_t arg);
int sys_gtty(int cmd);

/* Process info syscalls */
int sys_getpid(void);
int sys_getppid(void);
int sys_getuid(void);
int sys_getgid(void);
int sys_time(time_t* tloc);
int sys_gettimeofday(struct timeval* tv, struct timezone* tz);
int sys_setpgid(pid_t pid, pid_t pgid);
int sys_getpgrp(void);

/* Signal syscalls */
int sys_kill(pid_t pid, int sig);
int sys_signal(int sig, sig_handler_t handler);
int sys_sigaction(int sig, const sigaction_t* act, sigaction_t* oldact);
void sys_sigreturn(void);
int sys_nanosleep(const timespec_t *req, timespec_t *rem);

/* Memory syscalls */
int sys_brk(void* addr);
int sys_shm_open(const char *name, size_t size, int flags);
int sys_shm_unlink(const char *name);
void *sys_shm_map(int id, void *addr, int flags);
int sys_shm_unmap(void *addr, size_t size);
int sys_shutdown(void);

/* Additional process syscalls */
int sys_dup(int oldfd);
int sys_dup2(int oldfd, int newfd);
int sys_pipe(int pipefd[2]);
int sys_chdir(const char* path);
int sys_getcwd(char* buf, size_t size);
int sys_sysinfo(struct sysinfo_response *resp);

#endif

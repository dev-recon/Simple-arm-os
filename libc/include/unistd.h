#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>

/* File descriptors */
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

/* Syscalls de base */
int write(int fd, const void* buf, size_t count);
int read(int fd, void* buf, size_t count);
int open(const char* path, int flags, mode_t mode);
off_t lseek(int fd, off_t offset, int whence);
int close(int fd);
void exit(int status) __attribute__((noreturn));

int mkdir(const char* path, int flags);
int rmdir(const char* path);
int unlink(const char* pathname);
int rename(const char* oldpath, const char* newpath);

/* Informations processus (temporaire — sera remplacé par /proc) */
struct proc_info {
    unsigned tid;
    int      pid;
    int      ppid;
    unsigned uid;
    unsigned gid;
    unsigned priority;
    unsigned switches;
    unsigned cpu_pct_x10;
    unsigned stack_kb;
    unsigned heap_kb;
    unsigned vm_kb;
    unsigned rss_kb;
    unsigned l2_tables;
    unsigned page_faults;
    unsigned cow_faults;
    unsigned stack_faults;
    char     name[32];
    char     state;
    char     type;
    char     _pad[2];
};

struct sysinfo_response {
    unsigned         mem_total_kb;
    unsigned         mem_free_kb;
    int              proc_count;
    unsigned         _pad;
    unsigned         tasks_created;
    unsigned         tasks_destroyed;
    unsigned         zombies_created;
    unsigned         zombies_reaped;
    unsigned         failed_forks;
    unsigned         scheduler_refused;
    unsigned         ready_queue_refused;
    unsigned         stack_pages_allocated;
    unsigned         stack_pages_freed;
    unsigned         asid_rollovers;
    struct proc_info procs[64];
};

int getsysinfo(struct sysinfo_response *resp);


int dup(int oldfd);

int dup2(int oldfd, int newfd);

int pipe(int pipefd[2]);

int chdir(const char* path);

int _getcwd(char* buf, size_t size);

int access(const char* pathname, int mode);

int umask(int mask);

int chmod(const char* pathname, mode_t mode);

int chown(const char* pathname, uid_t owner, gid_t group);



/* Processus */
#define WNOHANG 1

int getpid(void);
int getppid(void);
int getuid(void);
int getgid(void);
int setpgid(pid_t pid, pid_t pgid);
int getpgrp(void);
int fork(void);
int execve(const char* filename, char* const argv[], char* const envp[]);
int waitpid(int pid, int* status, int options);
int kill(pid_t pid, int sig);

/* Syscall générique */
long syscall(long number, ...);

/* Gestion mémoire */
//void *brk(void *addr);
void *sbrk(void *addr);
int print(const char* msg);

#define SHM_O_CREAT 0x01
#define SHM_O_EXCL  0x02
#define SHM_RDONLY  0x01
#define SHM_RDWR    0x02

int shm_open(const char *name, size_t size, int flags);
int shm_unlink(const char *name);
void *shm_map(int id, void *addr, int flags);
int shm_unmap(void *addr, size_t size);
int sys_shutdown(void);

/* Équivalent uart_putc */
static inline int putc_tty(char c) {
    return write(STDOUT_FILENO, &c, 1) == 1 ? 0 : -1;
}

/* Équivalent uart_getc */
static inline int getc_tty(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) == 1) {
        return (unsigned char)c;
    }
    return -1;  /* EOF ou erreur */
}


#endif

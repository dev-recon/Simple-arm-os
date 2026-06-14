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

/* Informations processus (temporaire — sera remplacé par /proc) */
struct proc_info {
    int      pid;
    int      ppid;
    unsigned priority;
    unsigned switches;
    unsigned cpu_pct_x10;
    unsigned stack_kb;
    unsigned heap_kb;
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

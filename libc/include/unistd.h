#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>

/* File descriptors */
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

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
int getpid(void);
int getppid(void);
int fork(void);
int execve(const char* filename, char* const argv[], char* const envp[]);
int waitpid(int pid, int* status, int options);
int kill(pid_t pid, int sig);

/* Syscall générique */
long syscall(long number, ...);

/* Gestion mémoire */
void *brk(void *addr);
void *sbrk(void *addr);
int print(const char* msg);

#endif
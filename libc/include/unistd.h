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
void exit(int status) __attribute__((noreturn));

/* Processus */
int getpid(void);
int getppid(void);
int fork(void);
int execve(const char* filename, char* const argv[], char* const envp[]);
int waitpid(int pid, int* status, int options);


/* Syscall générique */
long syscall(long number, ...);

#endif
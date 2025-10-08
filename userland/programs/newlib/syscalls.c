/* syscalls.c - Interface entre Newlib et vos syscalls */
#include "../../sysroot/arm-none-eabi/include/sys/stat.h"
#include <sys/types.h>
#include <sys/times.h>
#include <errno.h>

/* Inclure vos prototypes de syscalls */
extern long sys_read(int fd, void *buf, unsigned long count);
extern long sys_write(int fd, const void *buf, unsigned long count);
extern long sys_open(const char *pathname, int flags, int mode);
extern long sys_close(int fd);
extern long sys_lseek(int fd, long offset, int whence);
extern long sys_unlink(const char *pathname);
extern void sys_exit(int status);
extern long sys_getpid(void);
extern long sys_brk(unsigned long brk);

/* Variables globales requises par Newlib */
char *__env[1] = { 0 };
char **environ = __env;

/* Implémentation des syscalls pour Newlib */
int _read(int fd, void *buf, size_t count) {
    long result = sys_read(fd, buf, count);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

int _write(int fd, const void *buf, size_t count) {
    long result = sys_write(fd, buf, count);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

int _open(const char *pathname, int flags, int mode) {
    long result = sys_open(pathname, flags, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

int _close(int fd) {
    long result = sys_close(fd);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

off_t _lseek(int fd, off_t offset, int whence) {
    long result = sys_lseek(fd, offset, whence);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

int _unlink(const char *pathname) {
    long result = sys_unlink(pathname);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

void _exit(int status) {
    sys_exit(status);
    while(1);  /* Ne devrait jamais arriver */
}

pid_t _getpid(void) {
    return sys_getpid();
}

/* Gestion mémoire via brk */
static char *heap_end = 0;

void *_sbrk(ptrdiff_t incr) {
    char *prev_heap_end;
    
    if (heap_end == 0) {
        /* Premier appel - obtenir le break actuel */
        heap_end = (char*)sys_brk(0);
    }
    
    prev_heap_end = heap_end;
    
    if (sys_brk((unsigned long)(heap_end + incr)) == -1) {
        errno = ENOMEM;
        return (void*)-1;
    }
    
    heap_end += incr;
    return prev_heap_end;
}

/* Stubs pour les syscalls non implémentés */
int _fstat(int fd, struct stat *st) {
    if (!st) {
        errno = EFAULT;
        return -1;
    }
    
    /* Simuler un fichier régulier */
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0644;
    st->st_nlink = 1;
    st->st_blksize = 512;
    
    return 0;
}

int _stat(const char *pathname, struct stat *st) {
    /* Pas encore implémenté */
    errno = ENOSYS;
    return -1;
}

int _isatty(int fd) {
    /* Considérer stdin/stdout/stderr comme des TTY */
    return (fd >= 0 && fd <= 2) ? 1 : 0;
}

int _kill(int pid, int sig) {
    errno = ENOSYS;
    return -1;
}

clock_t _times(struct tms *buf) {
    errno = ENOSYS;
    return -1;
}

int _link(const char *oldpath, const char *newpath) {
    errno = ENOSYS;
    return -1;
}

int _fork(void) {
    errno = ENOSYS;
    return -1;
}

int _execve(const char *pathname, char *const argv[], char *const envp[]) {
    errno = ENOSYS;
    return -1;
}

int _wait(int *status) {
    errno = ENOSYS;
    return -1;
}
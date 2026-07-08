#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define POPEN_SLOTS 32

typedef struct popen_slot {
    FILE *fp;
    pid_t pid;
} popen_slot_t;

static popen_slot_t popen_slots[POPEN_SLOTS];

static int popen_find_free_slot(void)
{
    int i;

    for (i = 0; i < POPEN_SLOTS; i++) {
        if (popen_slots[i].fp == NULL)
            return i;
    }

    errno = EMFILE;
    return -1;
}

static int popen_find_slot(FILE *fp)
{
    int i;

    for (i = 0; i < POPEN_SLOTS; i++) {
        if (popen_slots[i].fp == fp)
            return i;
    }

    errno = EINVAL;
    return -1;
}

FILE *popen(const char *command, const char *mode)
{
    int pipefd[2];
    int slot;
    pid_t pid;
    FILE *fp;
    char *const argv[] = { "mash", "-c", (char *)command, NULL };

    if (!command || !mode || !mode[0] || mode[1] != '\0' ||
        (mode[0] != 'r' && mode[0] != 'w')) {
        errno = EINVAL;
        return NULL;
    }

    slot = popen_find_free_slot();
    if (slot < 0)
        return NULL;

    if (pipe(pipefd) < 0)
        return NULL;

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        if (mode[0] == 'r') {
            close(pipefd[0]);
            if (dup2(pipefd[1], STDOUT_FILENO) < 0)
                _exit(127);
            close(pipefd[1]);
        } else {
            close(pipefd[1]);
            if (dup2(pipefd[0], STDIN_FILENO) < 0)
                _exit(127);
            close(pipefd[0]);
        }

        execve("/sbin/mash", argv, environ);
        _exit(127);
    }

    if (mode[0] == 'r') {
        close(pipefd[1]);
        fp = fdopen(pipefd[0], "r");
        if (!fp)
            close(pipefd[0]);
    } else {
        close(pipefd[0]);
        fp = fdopen(pipefd[1], "w");
        if (!fp)
            close(pipefd[1]);
    }

    if (!fp) {
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        return NULL;
    }

    popen_slots[slot].fp = fp;
    popen_slots[slot].pid = pid;
    return fp;
}

int pclose(FILE *fp)
{
    int slot;
    pid_t pid;
    int status;
    int saved_errno;

    slot = popen_find_slot(fp);
    if (slot < 0)
        return -1;

    pid = popen_slots[slot].pid;
    popen_slots[slot].fp = NULL;
    popen_slots[slot].pid = -1;

    if (fclose(fp) == EOF) {
        saved_errno = errno;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        errno = saved_errno;
        return -1;
    }

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }

    return status;
}

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SIGTTIN
#define SIGTTIN 21
#endif
#ifndef SIGTTOU
#define SIGTTOU 22
#endif

static char *const init_envp[] = {
    "PATH=/bin:/usr/bin:/opt/kilo/bin",
    "HOME=/home/user",
    "USER=user",
    "PS1=mash$> ",
    NULL
};

static char *const root_envp[] = {
    "PATH=/bin:/usr/bin:/sbin:/opt/kilo/bin",
    "HOME=/root",
    "USER=root",
    "PS1=root# ",
    "MASH_BANNER=0",
    NULL
};

static int attach_stdio_to(const char *tty_path)
{
    int fd = open(tty_path, O_RDWR, 0);
    if (fd < 0)
        return -1;

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
        close(fd);
    return 0;
}

static int spawn_shell(void)
{
    char *const argv[] = { "mash", NULL };
    int pid;

    pid = fork();
    if (pid < 0) {
        perror("init: fork");
        return -1;
    }

    if (pid == 0) {
        chdir("/home/user");
        if (setgid(1000) < 0)
            perror("init: setgid");
        if (setuid(1000) < 0)
            perror("init: setuid");
        execve("/sbin/mash", argv, init_envp);
        perror("init: exec /sbin/mash");
        _exit(127);
    }

    return pid;
}

static int spawn_root_graphics_shell(void)
{
    char *const argv[] = { "mash", NULL };
    int pid;

    pid = fork();
    if (pid < 0) {
        perror("init: fork tty1");
        return -1;
    }

    if (pid == 0) {
        if (attach_stdio_to("/dev/tty1") < 0)
            _exit(0);
        chdir("/root");
        execve("/sbin/mash", argv, root_envp);
        perror("init: exec /sbin/mash tty1");
        _exit(127);
    }

    return pid;
}

int main(void)
{
    int shell_pid;
    int root_shell_pid;
    int waited;
    int status;

    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    chdir("/");

    root_shell_pid = spawn_root_graphics_shell();
    (void)root_shell_pid;

    while (1) {
        shell_pid = spawn_shell();
        if (shell_pid < 0) {
            sleep(1);
            continue;
        }

        while (1) {
            status = 0;
            waited = waitpid(-1, &status, 0);

            if (waited < 0) {
                if (errno == EINTR)
                    continue;
                perror("init: waitpid");
                break;
            }

            if (waited == shell_pid)
                break;

            /*
             * Reaped an orphan adopted by PID 1. Keep waiting for the login
             * shell so zombies do not accumulate under init.
             */
        }

        /*
         * PID 1 owns the console session for now. If mash unexpectedly exits,
         * restart it instead of leaving the system without an interactive shell.
         */
        fprintf(stderr, "init: shell exited, restarting\n");
        sleep(1);
    }
}

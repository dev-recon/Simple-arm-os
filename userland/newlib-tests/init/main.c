#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static char *const init_envp[] = {
    "PATH=/bin",
    "HOME=/home/user",
    "USER=user",
    "PS1=mash$> ",
    NULL
};

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
        execve("/bin/mash", argv, init_envp);
        perror("init: exec /bin/mash");
        _exit(127);
    }

    return pid;
}

int main(void)
{
    int shell_pid;
    int waited;
    int status;

    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    chdir("/");

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

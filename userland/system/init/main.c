/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/init/main.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

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

static int attach_stdio_fd(int fd)
{
    if (fd < 0)
        return -1;

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
        close(fd);
    return 0;
}

static int attach_stdio_to(const char *tty_path)
{
    int fd = open(tty_path, O_RDWR, 0);

    return attach_stdio_fd(fd);
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
        if (attach_stdio_to("/dev/tty0") < 0)
            perror("init: attach /dev/tty0");
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
    int tty_fd;
    int pid;

    tty_fd = open("/dev/tty1", O_RDWR, 0);
    if (tty_fd < 0) {
        fprintf(stderr, "init: tty1 unavailable, graphics shell disabled\n");
        return 0;
    }

    pid = fork();
    if (pid < 0) {
        perror("init: fork tty1");
        close(tty_fd);
        return -1;
    }

    if (pid == 0) {
        if (attach_stdio_fd(tty_fd) < 0)
            _exit(0);
        chdir("/root");
        execve("/sbin/mash", argv, root_envp);
        perror("init: exec /sbin/mash tty1");
        _exit(127);
    }

    close(tty_fd);
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

    shell_pid = -1;
    root_shell_pid = spawn_root_graphics_shell();

    while (1) {
        if (shell_pid < 0) {
            shell_pid = spawn_shell();
            if (shell_pid > 0)
                fprintf(stderr, "init: tty0 shell pid %d\n", shell_pid);
        }

        if (root_shell_pid < 0)
            root_shell_pid = spawn_root_graphics_shell();

        status = 0;
        waited = waitpid(-1, &status, 0);

        if (waited < 0) {
            if (errno == EINTR)
                continue;
            perror("init: waitpid");
            sleep(1);
            continue;
        }

        if (waited == shell_pid) {
            fprintf(stderr, "init: tty0 shell exited, restarting\n");
            shell_pid = -1;
        } else if (waited == root_shell_pid) {
            fprintf(stderr, "init: tty1 shell exited, restarting\n");
            root_shell_pid = -1;
        }

        /*
         * Other children are orphans adopted by PID 1. Reaping them here keeps
         * the system clean without coupling tty0 and tty1 lifetimes.
         */
    }
}

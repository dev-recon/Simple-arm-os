/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/renice.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

static void usage(void)
{
    printf("usage: renice priority [-p] pid...\n");
}

static int parse_pid(const char *s)
{
    int pid;

    if (!s || !*s)
        return -1;
    pid = atoi(s);
    return pid > 0 ? pid : -1;
}

int main(int argc, char **argv)
{
    int prio;
    int i;
    int status = 0;

    if (argc < 3) {
        usage();
        return 1;
    }

    prio = atoi(argv[1]);
    if (prio < -20 || prio > 19) {
        printf("renice: priority must be between -20 and 19\n");
        return 1;
    }

    i = 2;
    if (strcmp(argv[i], "-p") == 0) {
        i++;
        if (i >= argc) {
            usage();
            return 1;
        }
    }

    for (; i < argc; i++) {
        int pid = parse_pid(argv[i]);
        int old_prio;

        if (pid < 0) {
            printf("renice: invalid pid '%s'\n", argv[i]);
            status = 1;
            continue;
        }

        errno = 0;
        old_prio = getpriority(PRIO_PROCESS, pid);
        if (old_prio == -1 && errno != 0) {
            printf("renice: failed to read pid %d\n", pid);
            status = 1;
            continue;
        }

        if (setpriority(PRIO_PROCESS, pid, prio) < 0) {
            printf("renice: failed to set pid %d\n", pid);
            status = 1;
            continue;
        }

        printf("%d: old priority %d, new priority %d\n",
               pid, old_prio, prio);
    }

    return status;
}

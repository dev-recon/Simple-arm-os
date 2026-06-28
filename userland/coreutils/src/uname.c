/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/uname.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

int main(int argc, char **argv)
{
    int all = argc > 1 && strcmp(argv[1], "-a") == 0;
    struct utsname u;

    if (argc > 1 && !all) {
        printf("usage: uname [-a]\n");
        return 1;
    }

    if (uname(&u) < 0) {
        perror("uname");
        return 1;
    }

    if (all)
        printf("%s %s %s %s %s\n",
               u.sysname, u.nodename, u.release, u.version, u.machine);
    else
        printf("%s\n", u.sysname);

    return 0;
}

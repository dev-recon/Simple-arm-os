/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/dirname.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char *slash;
    char *end;

    if (argc < 2) {
        printf("usage: dirname PATH\n");
        return 1;
    }

    end = argv[1] + strlen(argv[1]);
    while (end > argv[1] + 1 && end[-1] == '/')
        *--end = '\0';

    slash = strrchr(argv[1], '/');
    if (!slash) {
        printf(".\n");
    } else if (slash == argv[1]) {
        printf("/\n");
    } else {
        while (slash > argv[1] && slash[-1] == '/')
            slash--;
        *slash = '\0';
        printf("%s\n", argv[1]);
    }

    return 0;
}

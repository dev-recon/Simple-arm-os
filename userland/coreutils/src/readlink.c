/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/readlink.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    char buf[512];
    int status = 0;

    if (argc < 2) {
        printf("Usage: readlink FILE...\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        int n = readlink(argv[i], buf, sizeof(buf) - 1);
        if (n < 0) {
            printf("readlink: cannot read '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        buf[n] = '\0';
        printf("%s\n", buf);
    }

    return status;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/pwd.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char cwd[256];

    if (!getcwd(cwd, sizeof(cwd))) {
        printf("pwd: getcwd failed\n");
        return 1;
    }

    printf("%s\n", cwd);
    return 0;
}

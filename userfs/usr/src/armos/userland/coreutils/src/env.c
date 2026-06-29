/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/env.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    for (char **p = environ; p && *p; p++)
        printf("%s\n", *p);

    return 0;
}

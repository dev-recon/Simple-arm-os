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

int main(int argc, char **argv)
{
    int all = argc > 1 && strcmp(argv[1], "-a") == 0;

    if (argc > 1 && !all) {
        printf("usage: uname [-a]\n");
        return 1;
    }

    if (all)
        printf("ArmOS armos 0.1 armv7l ARM Cortex-A15\n");
    else
        printf("ArmOS\n");

    return 0;
}

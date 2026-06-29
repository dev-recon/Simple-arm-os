/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/sleep.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: sleep <seconds>\n");
        return 1;
    }

    unsigned int seconds = (unsigned int)atoi(argv[1]);
    sleep(seconds);
    return 0;
}

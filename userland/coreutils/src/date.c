/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/date.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <time.h>

int main(int argc, char **argv)
{
    time_t now;
    struct tm *tm;
    char buf[64];

    (void)argv;
    if (argc > 1) {
        printf("date: setting date is not supported\n");
        return 1;
    }

    now = time(NULL);
    tm = localtime(&now);
    if (!tm) {
        printf("date: cannot read time\n");
        return 1;
    }

    if (strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S UTC %Y", tm) == 0)
        return 1;
    printf("%s\n", buf);
    return 0;
}

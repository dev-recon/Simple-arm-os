/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/uptime.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char buf[64];
    int fd = open("/proc/uptime", O_RDONLY, 0);
    int n;
    unsigned seconds;

    if (fd < 0) {
        printf("uptime: cannot open /proc/uptime\n");
        return 1;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 1;
    buf[n] = '\0';

    seconds = (unsigned)strtoul(buf, NULL, 10);
    printf("up %u days, %02u:%02u:%02u\n",
           seconds / 86400,
           (seconds / 3600) % 24,
           (seconds / 60) % 60,
           seconds % 60);
    return 0;
}

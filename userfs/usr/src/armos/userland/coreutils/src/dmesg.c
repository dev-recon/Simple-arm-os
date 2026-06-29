/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/dmesg.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[512];
    int fd = open("/proc/dmesg", O_RDONLY, 0);
    int n;
    int status = 0;

    if (fd < 0) {
        printf("dmesg: cannot open /proc/dmesg\n");
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, n) != n) {
            status = 1;
            break;
        }
    }

    if (n < 0)
        status = 1;
    close(fd);
    return status;
}

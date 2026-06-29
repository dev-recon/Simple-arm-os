/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/ttyinfo/ttyinfo.c
 * Layer: Userland / test or sample program
 * Description: Userland test, diagnostic, or sample application.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define TTY_BUF_SIZE 4096

int main(void)
{
    char buf[TTY_BUF_SIZE];
    int fd;
    int n;

    fd = open("/proc/tty", O_RDONLY, 0);
    if (fd < 0) {
        printf("ttyinfo: cannot open /proc/tty\n");
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, n) != n) {
            close(fd);
            return 1;
        }
    }

    close(fd);
    return n < 0 ? 1 : 0;
}

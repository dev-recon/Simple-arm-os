/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/netstat.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int show_file(const char *path)
{
    char buf[512];
    int fd = open(path, O_RDONLY, 0);
    int n;

    if (fd < 0) {
        printf("netstat: cannot open %s\n", path);
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0)
        write(STDOUT_FILENO, buf, n);

    close(fd);
    return n < 0 ? 1 : 0;
}

static void usage(void)
{
    printf("usage: netstat [-i] [-t] [-a]\n");
}

int main(int argc, char **argv)
{
    int show_ifaces = 0;
    int show_tcp = 0;
    int rc = 0;

    if (argc == 1) {
        show_ifaces = 1;
        show_tcp = 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0)
            show_ifaces = 1;
        else if (strcmp(argv[i], "-t") == 0)
            show_tcp = 1;
        else if (strcmp(argv[i], "-a") == 0) {
            show_ifaces = 1;
            show_tcp = 1;
        } else {
            usage();
            return 1;
        }
    }

    if (show_ifaces) {
        printf("Kernel Interface table\n");
        rc |= show_file("/proc/net/dev");
    }

    if (show_tcp) {
        if (show_ifaces)
            printf("\n");
        printf("Active Internet connections (TCP)\n");
        rc |= show_file("/proc/net/tcp");
    }

    return rc ? 1 : 0;
}

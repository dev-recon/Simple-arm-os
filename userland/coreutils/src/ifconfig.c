/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/ifconfig.c
 * Layer: Userland / network utilities
 *
 * Responsibilities:
 * - Display link, IPv4, DHCP and packet-counter state for ArmOS interfaces.
 * - Query the architecture-neutral network control device.
 *
 * Notes:
 * - Address mutation is intentionally deferred until the network control ABI
 *   has stable privilege and routing semantics.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IFCONFIG_BUFFER_SIZE 512

static void usage(void)
{
    fprintf(stderr, "usage: ifconfig [interface]\n");
}

int main(int argc, char **argv)
{
    char command[64];
    char buffer[IFCONFIG_BUFFER_SIZE];
    const char *interface = NULL;
    ssize_t count;
    int fd;

    if (argc > 2) {
        usage();
        return 1;
    }
    if (argc == 2)
        interface = argv[1];

    fd = open("/dev/netctl", O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "ifconfig: cannot open /dev/netctl: %s\n",
                strerror(errno));
        return 1;
    }

    if (interface)
        snprintf(command, sizeof(command), "show %s", interface);
    else
        snprintf(command, sizeof(command), "show");
    if (write(fd, command, strlen(command)) != (ssize_t)strlen(command)) {
        fprintf(stderr, "ifconfig: network query failed: %s\n",
                strerror(errno));
        close(fd);
        return 1;
    }

    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write(STDOUT_FILENO, buffer, (size_t)count) != count) {
            fprintf(stderr, "ifconfig: output failed: %s\n",
                    strerror(errno));
            close(fd);
            return 1;
        }
    }
    if (count < 0) {
        fprintf(stderr, "ifconfig: network response failed: %s\n",
                strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/write.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: write <file> <text>...\n");
        return 1;
    }

    int fd = open(argv[1], O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        printf("write: cannot open '%s'\n", argv[1]);
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        write(fd, argv[i], strlen(argv[i]));
        if (i < argc - 1)
            write(fd, " ", 1);
    }
    write(fd, "\n", 1);

    close(fd);
    return 0;
}

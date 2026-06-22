/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/tools/mount.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void usage(void)
{
    printf("usage: mount\n");
    printf("       mount -t TYPE SOURCE TARGET\n");
}

static int print_mounts(void)
{
    char buf[512];
    char line[160];
    int line_len = 0;
    int fd;
    int n;
    int status = 0;

    fd = open("/proc/mounts", O_RDONLY, 0);
    if (fd < 0) {
        printf("mount: cannot open /proc/mounts\n");
        return 1;
    }

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < n; i++) {
            if (buf[i] == '\n' || line_len >= (int)sizeof(line) - 1) {
                char source[64];
                char target[64];
                char type[32];
                char opts[48] = "rw";

                line[line_len] = '\0';
                if (sscanf(line, "%63s %63s %31s %47s", source, target, type, opts) >= 3) {
                    printf("%s on %s type %s (%s)\n", source, target, type, opts);
                }
                line_len = 0;
            } else {
                line[line_len++] = buf[i];
            }
        }
    }

    if (line_len > 0) {
        char source[64];
        char target[64];
        char type[32];
        char opts[48] = "rw";
        line[line_len] = '\0';
        if (sscanf(line, "%63s %63s %31s %47s", source, target, type, opts) >= 3)
            printf("%s on %s type %s (%s)\n", source, target, type, opts);
    }

    if (n < 0)
        status = 1;

    close(fd);
    return status;
}

int main(int argc, char** argv)
{
    const char* type = NULL;
    const char* source;
    const char* target;
    int arg = 1;

    if (argc == 1)
        return print_mounts();

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    if (argc > 2 && strcmp(argv[arg], "-t") == 0) {
        type = argv[arg + 1];
        arg += 2;
    }

    if (!type || argc - arg != 2) {
        usage();
        return 1;
    }

    source = argv[arg];
    target = argv[arg + 1];

    if (mount(source, target, type, 0, NULL) < 0) {
        printf("mount: cannot mount %s on %s as %s\n", source, target, type);
        return errno ? errno : 1;
    }

    return 0;
}

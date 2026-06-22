/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/tools/umount.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void usage(void)
{
    printf("usage: umount TARGET...\n");
}

int main(int argc, char** argv)
{
    int status = 0;

    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        usage();
        return argc < 2 ? 1 : 0;
    }

    for (int i = 1; i < argc; i++) {
        if (umount(argv[i]) < 0) {
            printf("umount: cannot unmount %s\n", argv[i]);
            status = errno ? errno : 1;
        }
    }

    return status;
}

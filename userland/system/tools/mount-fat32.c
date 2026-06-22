/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/tools/mount-fat32.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

#include <errno.h>
#include <stdio.h>

int main(void)
{
    if (mount("/dev/virtio0p2", "/mnt", "fat32", 0, NULL) < 0) {
        printf("mount-fat32: cannot mount /dev/virtio0p2 on /mnt\n");
        return errno ? errno : 1;
    }

    return 0;
}

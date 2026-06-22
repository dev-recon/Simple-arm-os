/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/mount.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_MOUNT_H
#define _KERNEL_MOUNT_H

#include <kernel/disk_layout.h>

#define FSTAB_PATH "/etc/fstab"

int vfs_mount_from_fstab(const char* path);
int vfs_mount_fat32_partition(const disk_partition_t* part);
int vfs_mount_user(const char* source, const char* target, const char* fstype,
                   uint32_t flags, const void* data);

#endif

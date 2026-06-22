/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/disk_layout.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_DISK_LAYOUT_H
#define _KERNEL_DISK_LAYOUT_H

#include <kernel/types.h>

#define DISK_SECTOR_SIZE       512ULL
#define DISK_EXT2_SIZE_MB      64ULL
#define DISK_FAT32_SIZE_MB     64ULL
#define DISK_MB_TO_SECTORS(mb) ((uint64_t)(mb) * 1024ULL * 1024ULL / DISK_SECTOR_SIZE)

typedef enum {
    DISK_FS_EXT2 = 1,
    DISK_FS_FAT32 = 2,
} disk_fs_type_t;

typedef enum {
    DISK_PART_EXT2_ROOT = 0,
    DISK_PART_FAT32_MNT = 1,
    DISK_PART_COUNT
} disk_partition_id_t;

typedef struct {
    disk_partition_id_t id;
    disk_fs_type_t fs_type;
    const char* name;
    const char* mountpoint;
    uint64_t lba_start;
    uint64_t sector_count;
} disk_partition_t;

static const disk_partition_t kernel_disk_partitions[DISK_PART_COUNT] = {
    {
        .id = DISK_PART_EXT2_ROOT,
        .fs_type = DISK_FS_EXT2,
        .name = "virtio0p1",
        .mountpoint = "/",
        .lba_start = 0,
        .sector_count = DISK_MB_TO_SECTORS(DISK_EXT2_SIZE_MB),
    },
    {
        .id = DISK_PART_FAT32_MNT,
        .fs_type = DISK_FS_FAT32,
        .name = "virtio0p2",
        .mountpoint = "/mnt",
        .lba_start = DISK_MB_TO_SECTORS(DISK_EXT2_SIZE_MB),
        .sector_count = DISK_MB_TO_SECTORS(DISK_FAT32_SIZE_MB),
    },
};

static inline const disk_partition_t* disk_partition_get(disk_partition_id_t id)
{
    if (id >= DISK_PART_COUNT) {
        return NULL;
    }
    return &kernel_disk_partitions[id];
}

#endif

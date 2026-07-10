/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/fs/disk_layout.c
 * Layer: Kernel / filesystem
 * Description: Runtime disk partition layout discovery.
 */

#include <kernel/disk_layout.h>
#include <kernel/block_device.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>

#define MBR_PARTITION_OFFSET 446
#define MBR_SIGNATURE_OFFSET 510
#define MBR_PARTITION_SIZE   16

#define MBR_TYPE_EXT2        0x83
#define MBR_TYPE_FAT32_CHS   0x0B
#define MBR_TYPE_FAT32_LBA   0x0C
#define MBR_TYPE_HIDDEN_FAT32_CHS 0x1B
#define MBR_TYPE_HIDDEN_FAT32_LBA 0x1C
#define DISK_PART_NAME_LEN   16

static char runtime_partition_names[DISK_PART_COUNT][DISK_PART_NAME_LEN];

disk_partition_t kernel_disk_partitions[DISK_PART_COUNT] = {
    {
        .id = DISK_PART_EXT2_ROOT,
        .fs_type = DISK_FS_EXT2,
        .name = "disk0p1",
        .mountpoint = "/",
        .lba_start = DISK_MB_TO_SECTORS(DISK_EXT2_START_MB),
        .sector_count = DISK_MB_TO_SECTORS(DISK_EXT2_SIZE_MB),
    },
    {
        .id = DISK_PART_FAT32_MNT,
        .fs_type = DISK_FS_FAT32,
        .name = "disk0p2",
        .mountpoint = "/mnt",
        .lba_start = DISK_MB_TO_SECTORS(DISK_FAT32_START_MB),
        .sector_count = DISK_MB_TO_SECTORS(DISK_FAT32_SIZE_MB),
    },
};

static void disk_layout_refresh_names(void)
{
    const char* block_name = blk_get_name();

    if (!block_name || block_name[0] == '\0' || strcmp(block_name, "none") == 0) {
        block_name = "disk0";
    }

    for (uint32_t i = 0; i < DISK_PART_COUNT; i++) {
        snprintf(runtime_partition_names[i],
                 sizeof(runtime_partition_names[i]),
                 "%sp%u", block_name, i + 1);
        kernel_disk_partitions[i].name = runtime_partition_names[i];
    }
}

static uint32_t read_le32(const uint8_t* p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

const disk_partition_t* disk_partition_get(disk_partition_id_t id)
{
    if (id >= DISK_PART_COUNT) {
        return NULL;
    }
    return &kernel_disk_partitions[id];
}

static void set_partition_name(disk_partition_id_t id, uint32_t partition_number)
{
    const char* block_name = blk_get_name();

    if (!block_name || block_name[0] == '\0' || strcmp(block_name, "none") == 0)
        block_name = "disk0";

    snprintf(runtime_partition_names[id],
             sizeof(runtime_partition_names[id]),
             "%sp%u", block_name, partition_number);
    kernel_disk_partitions[id].name = runtime_partition_names[id];
}

static void update_partition(disk_partition_id_t id,
                             uint32_t partition_number,
                             uint32_t start_lba,
                             uint32_t sectors)
{
    set_partition_name(id, partition_number);
    kernel_disk_partitions[id].lba_start = start_lba;
    kernel_disk_partitions[id].sector_count = sectors;
}

bool disk_layout_init_from_mbr(void)
{
    uint8_t sector[512];
    bool found_ext2 = false;
    bool found_fat32 = false;

    disk_layout_refresh_names();

    if (blk_read_sectors(0, 1, sector) < 0) {
        KERROR("[DISK] Could not read MBR sector; using compiled layout\n");
        return false;
    }

    if (sector[MBR_SIGNATURE_OFFSET] != 0x55 ||
        sector[MBR_SIGNATURE_OFFSET + 1] != 0xAA) {
        KINFO("[DISK] No MBR signature; using compiled layout\n");
        return false;
    }

    for (int i = 0; i < 4; i++) {
        const uint8_t* entry = sector + MBR_PARTITION_OFFSET + i * MBR_PARTITION_SIZE;
        uint8_t type = entry[4];
        uint32_t start_lba = read_le32(entry + 8);
        uint32_t sectors = read_le32(entry + 12);

        if (type == 0 || start_lba == 0 || sectors == 0) {
            continue;
        }

        if (!found_ext2 && type == MBR_TYPE_EXT2) {
            update_partition(DISK_PART_EXT2_ROOT, (uint32_t)i + 1, start_lba, sectors);
            found_ext2 = true;
            continue;
        }

        if (!found_fat32 &&
            (type == MBR_TYPE_FAT32_CHS ||
             type == MBR_TYPE_FAT32_LBA ||
             type == MBR_TYPE_HIDDEN_FAT32_CHS ||
             type == MBR_TYPE_HIDDEN_FAT32_LBA)) {
            update_partition(DISK_PART_FAT32_MNT, (uint32_t)i + 1, start_lba, sectors);
            found_fat32 = true;
            continue;
        }
    }

    KINFO("[DISK] MBR %s: ext2 LBA=%u sectors=%u, fat32 LBA=%u sectors=%u\n",
          found_ext2 ? "parsed" : "partial",
          (uint32_t)kernel_disk_partitions[DISK_PART_EXT2_ROOT].lba_start,
          (uint32_t)kernel_disk_partitions[DISK_PART_EXT2_ROOT].sector_count,
          (uint32_t)kernel_disk_partitions[DISK_PART_FAT32_MNT].lba_start,
          (uint32_t)kernel_disk_partitions[DISK_PART_FAT32_MNT].sector_count);

    return found_ext2;
}

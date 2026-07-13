/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/ext2_reader.h
 * Layer: Kernel / read-only filesystem acquisition
 *
 * Responsibilities:
 * - Define a dependency-free, callback-driven ext2 reader.
 * - Expose bounded path lookup plus complete and ranged regular-file reads.
 *
 * Notes:
 * - This interface is used before the persistent VFS and block cache exist.
 */

#ifndef _KERNEL_EXT2_READER_H
#define _KERNEL_EXT2_READER_H

#include <kernel/types.h>

typedef int (*ext2_reader_read_sectors_t)(void *owner, uint64_t lba,
                                          uint32_t count, void *buffer);

typedef struct {
    void *owner;
    ext2_reader_read_sectors_t read_sectors;
    uint8_t *scratch;
    size_t scratch_size;
    uint64_t partition_lba;
    uint32_t block_size;
    uint32_t blocks_per_group;
    uint32_t inodes_per_group;
    uint32_t inode_size;
    uint32_t first_data_block;
} ext2_reader_t;

int ext2_reader_init(ext2_reader_t *reader, void *owner,
                     ext2_reader_read_sectors_t read_sectors,
                     uint64_t partition_lba, void *scratch,
                     size_t scratch_size);
int ext2_reader_file_size(ext2_reader_t *reader, const char *path,
                          size_t *file_size);
int ext2_reader_read_file(ext2_reader_t *reader, const char *path,
                          void *buffer, size_t capacity,
                          size_t *file_size);
ssize_t ext2_reader_read_range(ext2_reader_t *reader, const char *path,
                               size_t offset, void *buffer, size_t length);

#endif /* _KERNEL_EXT2_READER_H */

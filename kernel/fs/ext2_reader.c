/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/fs/ext2_reader.c
 * Layer: Kernel / read-only filesystem acquisition
 *
 * Responsibilities:
 * - Resolve absolute paths in an ext2 filesystem without the heap or VFS.
 * - Read complete files or byte ranges through direct and indirect blocks.
 * - Validate all on-disk offsets, record lengths and caller capacities.
 *
 * Notes:
 * - Symlinks, double-indirect blocks, writes and concurrent readers are not
 *   part of this early acquisition contract.
 */

#include <kernel/ext2_reader.h>

#define EXT2_SUPERBLOCK_OFFSET       1024u
#define EXT2_SUPERBLOCK_SIZE         1024u
#define EXT2_MAGIC_OFFSET            56u
#define EXT2_MAGIC                   0xEF53u
#define EXT2_FIRST_DATA_BLOCK_OFFSET 20u
#define EXT2_LOG_BLOCK_SIZE_OFFSET   24u
#define EXT2_BLOCKS_PER_GROUP_OFFSET 32u
#define EXT2_INODES_PER_GROUP_OFFSET 40u
#define EXT2_SUPER_INODE_SIZE_OFFSET 88u
#define EXT2_FEATURE_INCOMPAT_OFFSET 96u
#define EXT2_FEATURE_FILETYPE        0x00000002u
#define EXT2_GROUP_DESC_SIZE         32u
#define EXT2_GROUP_INODE_TABLE       8u
#define EXT2_ROOT_INODE              2u
#define EXT2_INODE_MODE_OFFSET       0u
#define EXT2_INODE_SIZE_OFFSET       4u
#define EXT2_INODE_BLOCKS_OFFSET     40u
#define EXT2_INODE_POINTERS          15u
#define EXT2_DIRECT_POINTERS         12u
#define EXT2_SINGLE_INDIRECT         12u
#define EXT2_MODE_TYPE_MASK          0xF000u
#define EXT2_MODE_DIRECTORY          0x4000u
#define EXT2_MODE_REGULAR            0x8000u
#define EXT2_MAX_COMPONENT           63u
#define EXT2_SECTOR_SIZE             512u

typedef struct {
    uint16_t mode;
    uint32_t size;
    uint32_t blocks[EXT2_INODE_POINTERS];
} ext2_reader_inode_t;

static uint16_t read_le16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t read_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static int read_block(ext2_reader_t *reader, uint32_t block)
{
    uint64_t sectors_per_block;
    uint64_t relative_lba;

    if (!reader || block == 0 || reader->block_size < EXT2_SECTOR_SIZE ||
        reader->block_size > reader->scratch_size ||
        reader->block_size % EXT2_SECTOR_SIZE != 0)
        return -1;
    sectors_per_block = reader->block_size / EXT2_SECTOR_SIZE;
    relative_lba = (uint64_t)block * sectors_per_block;
    if (relative_lba > ~(uint64_t)0 - reader->partition_lba)
        return -1;
    return reader->read_sectors(
        reader->owner, reader->partition_lba + relative_lba,
        (uint32_t)sectors_per_block, reader->scratch);
}

static int read_inode(ext2_reader_t *reader, uint32_t inode_number,
                      ext2_reader_inode_t *inode)
{
    uint32_t group;
    uint32_t local;
    uint32_t descriptor_block;
    uint32_t descriptor_offset;
    uint32_t inode_table;
    uint32_t inode_block;
    uint32_t inode_offset;
    const uint8_t *disk_inode;
    unsigned int index;

    if (!reader || !inode || inode_number == 0 ||
        reader->inodes_per_group == 0 || reader->inode_size < 128u ||
        reader->inode_size > reader->block_size)
        return -1;
    group = (inode_number - 1u) / reader->inodes_per_group;
    local = (inode_number - 1u) % reader->inodes_per_group;
    descriptor_block = reader->first_data_block + 1u +
        (group * EXT2_GROUP_DESC_SIZE) / reader->block_size;
    descriptor_offset = (group * EXT2_GROUP_DESC_SIZE) % reader->block_size;
    if (descriptor_offset + EXT2_GROUP_DESC_SIZE > reader->block_size ||
        read_block(reader, descriptor_block) != 0)
        return -1;
    inode_table = read_le32(reader->scratch + descriptor_offset +
                            EXT2_GROUP_INODE_TABLE);
    if (inode_table == 0)
        return -1;
    inode_block = inode_table +
        (local * reader->inode_size) / reader->block_size;
    inode_offset = (local * reader->inode_size) % reader->block_size;
    if (inode_offset + reader->inode_size > reader->block_size ||
        read_block(reader, inode_block) != 0)
        return -1;
    disk_inode = reader->scratch + inode_offset;
    inode->mode = read_le16(disk_inode + EXT2_INODE_MODE_OFFSET);
    inode->size = read_le32(disk_inode + EXT2_INODE_SIZE_OFFSET);
    for (index = 0; index < EXT2_INODE_POINTERS; index++)
        inode->blocks[index] = read_le32(
            disk_inode + EXT2_INODE_BLOCKS_OFFSET + index * 4u);
    return 0;
}

static int inode_data_block(ext2_reader_t *reader,
                            const ext2_reader_inode_t *inode,
                            uint32_t logical_block, uint32_t *disk_block)
{
    uint32_t indirect_index;

    if (!reader || !inode || !disk_block)
        return -1;
    if (logical_block < EXT2_DIRECT_POINTERS) {
        *disk_block = inode->blocks[logical_block];
        return 0;
    }
    indirect_index = logical_block - EXT2_DIRECT_POINTERS;
    if (indirect_index >= reader->block_size / sizeof(uint32_t) ||
        inode->blocks[EXT2_SINGLE_INDIRECT] == 0 ||
        read_block(reader, inode->blocks[EXT2_SINGLE_INDIRECT]) != 0)
        return -1;
    *disk_block = read_le32(reader->scratch + indirect_index * 4u);
    return 0;
}

static bool component_matches(const uint8_t *name, uint8_t name_length,
                              const char *component,
                              uint32_t component_length)
{
    uint32_t index;

    if (name_length != component_length)
        return false;
    for (index = 0; index < component_length; index++) {
        if (name[index] != (uint8_t)component[index])
            return false;
    }
    return true;
}

static int lookup_child(ext2_reader_t *reader,
                        const ext2_reader_inode_t *directory,
                        const char *component, uint32_t component_length,
                        uint32_t *inode_number)
{
    uint32_t logical_block;
    uint32_t remaining;

    if (!reader || !directory || !component || !inode_number ||
        component_length == 0 || component_length > EXT2_MAX_COMPONENT ||
        (directory->mode & EXT2_MODE_TYPE_MASK) != EXT2_MODE_DIRECTORY)
        return -1;
    remaining = directory->size;
    for (logical_block = 0; remaining > 0; logical_block++) {
        uint32_t disk_block;
        uint32_t block_bytes = remaining < reader->block_size ?
            remaining : reader->block_size;
        uint32_t offset = 0;

        if (inode_data_block(reader, directory, logical_block,
                             &disk_block) != 0 ||
            disk_block == 0 ||
            read_block(reader, disk_block) != 0)
            return -1;
        while (offset + 8u <= block_bytes) {
            const uint8_t *entry = reader->scratch + offset;
            uint32_t entry_inode = read_le32(entry);
            uint16_t record_length = read_le16(entry + 4u);
            uint8_t name_length = entry[6];

            if (record_length < 8u || (record_length & 3u) != 0 ||
                offset + record_length > block_bytes ||
                name_length > record_length - 8u)
                return -1;
            if (entry_inode != 0 && component_matches(
                    entry + 8u, name_length, component,
                    component_length)) {
                *inode_number = entry_inode;
                return 0;
            }
            offset += record_length;
        }
        remaining -= block_bytes;
    }
    return -1;
}

static int lookup_path(ext2_reader_t *reader, const char *path,
                       ext2_reader_inode_t *inode)
{
    ext2_reader_inode_t current;
    uint32_t inode_number = EXT2_ROOT_INODE;
    size_t cursor = 0;

    if (!reader || !path || !inode || path[0] != '/' ||
        read_inode(reader, inode_number, &current) != 0)
        return -1;
    while (path[cursor] == '/')
        cursor++;
    while (path[cursor] != '\0') {
        size_t start = cursor;
        uint32_t length;

        while (path[cursor] != '\0' && path[cursor] != '/')
            cursor++;
        length = (uint32_t)(cursor - start);
        if (lookup_child(reader, &current, path + start, length,
                         &inode_number) != 0 ||
            read_inode(reader, inode_number, &current) != 0)
            return -1;
        while (path[cursor] == '/')
            cursor++;
    }
    *inode = current;
    return 0;
}

int ext2_reader_init(ext2_reader_t *reader, void *owner,
                     ext2_reader_read_sectors_t read_sectors,
                     uint64_t partition_lba, void *scratch,
                     size_t scratch_size)
{
    uint8_t *bytes = scratch;
    uint32_t log_block_size;
    uint32_t incompat;

    if (!reader || !read_sectors || !scratch ||
        scratch_size < EXT2_SUPERBLOCK_SIZE ||
        read_sectors(owner,
                     partition_lba +
                         EXT2_SUPERBLOCK_OFFSET / EXT2_SECTOR_SIZE,
                     EXT2_SUPERBLOCK_SIZE / EXT2_SECTOR_SIZE,
                     scratch) != 0 ||
        read_le16(bytes + EXT2_MAGIC_OFFSET) != EXT2_MAGIC)
        return -1;
    log_block_size = read_le32(bytes + EXT2_LOG_BLOCK_SIZE_OFFSET);
    if (log_block_size > 2u)
        return -1;
    incompat = read_le32(bytes + EXT2_FEATURE_INCOMPAT_OFFSET);
    if ((incompat & ~EXT2_FEATURE_FILETYPE) != 0)
        return -1;
    reader->owner = owner;
    reader->read_sectors = read_sectors;
    reader->scratch = scratch;
    reader->scratch_size = scratch_size;
    reader->partition_lba = partition_lba;
    reader->block_size = 1024u << log_block_size;
    reader->blocks_per_group = read_le32(
        bytes + EXT2_BLOCKS_PER_GROUP_OFFSET);
    reader->inodes_per_group = read_le32(
        bytes + EXT2_INODES_PER_GROUP_OFFSET);
    reader->inode_size = read_le16(bytes + EXT2_SUPER_INODE_SIZE_OFFSET);
    reader->first_data_block = read_le32(
        bytes + EXT2_FIRST_DATA_BLOCK_OFFSET);
    if (reader->inode_size == 0)
        reader->inode_size = 128u;
    if (reader->block_size > scratch_size ||
        reader->blocks_per_group == 0 ||
        reader->inodes_per_group == 0 ||
        reader->inode_size < 128u ||
        reader->inode_size > reader->block_size)
        return -1;
    return 0;
}

int ext2_reader_file_size(ext2_reader_t *reader, const char *path,
                          size_t *file_size)
{
    ext2_reader_inode_t inode;

    if (!file_size || lookup_path(reader, path, &inode) != 0 ||
        (inode.mode & EXT2_MODE_TYPE_MASK) != EXT2_MODE_REGULAR)
        return -1;
    *file_size = inode.size;
    return 0;
}

int ext2_reader_path_info(ext2_reader_t *reader, const char *path,
                          ext2_reader_path_info_t *info)
{
    ext2_reader_inode_t inode;
    uint16_t type;

    if (!info || lookup_path(reader, path, &inode) != 0)
        return -1;
    type = inode.mode & EXT2_MODE_TYPE_MASK;
    if (type == EXT2_MODE_REGULAR)
        info->type = EXT2_READER_PATH_REGULAR;
    else if (type == EXT2_MODE_DIRECTORY)
        info->type = EXT2_READER_PATH_DIRECTORY;
    else
        return -1;
    info->size = inode.size;
    return 0;
}

int ext2_reader_read_file(ext2_reader_t *reader, const char *path,
                          void *buffer, size_t capacity,
                          size_t *file_size)
{
    ext2_reader_inode_t inode;
    uint8_t *destination = buffer;
    uint32_t logical_block;
    size_t copied = 0;

    if (!buffer || !file_size || lookup_path(reader, path, &inode) != 0 ||
        (inode.mode & EXT2_MODE_TYPE_MASK) != EXT2_MODE_REGULAR ||
        inode.size > capacity)
        return -1;
    for (logical_block = 0; copied < inode.size; logical_block++) {
        uint32_t disk_block;
        size_t chunk = inode.size - copied;
        size_t index;

        if (chunk > reader->block_size)
            chunk = reader->block_size;
        if (inode_data_block(reader, &inode, logical_block,
                             &disk_block) != 0)
            return -1;
        if (disk_block == 0) {
            for (index = 0; index < chunk; index++)
                destination[copied + index] = 0;
        } else {
            if (read_block(reader, disk_block) != 0)
                return -1;
            for (index = 0; index < chunk; index++)
                destination[copied + index] = reader->scratch[index];
        }
        copied += chunk;
    }
    *file_size = copied;
    return 0;
}

ssize_t ext2_reader_read_range(ext2_reader_t *reader, const char *path,
                               size_t offset, void *buffer, size_t length)
{
    ext2_reader_inode_t inode;
    uint8_t *destination = buffer;
    size_t remaining;
    size_t copied = 0;

    if ((!buffer && length != 0) || lookup_path(reader, path, &inode) != 0 ||
        (inode.mode & EXT2_MODE_TYPE_MASK) != EXT2_MODE_REGULAR)
        return -1;
    if (offset >= inode.size || length == 0)
        return 0;
    remaining = inode.size - offset;
    if (remaining > length)
        remaining = length;

    while (copied < remaining) {
        size_t file_offset = offset + copied;
        uint32_t logical_block =
            (uint32_t)(file_offset / reader->block_size);
        size_t block_offset = file_offset % reader->block_size;
        size_t chunk = reader->block_size - block_offset;
        uint32_t disk_block;
        size_t index;

        if (chunk > remaining - copied)
            chunk = remaining - copied;
        if (inode_data_block(reader, &inode, logical_block,
                             &disk_block) != 0)
            return -1;
        if (disk_block == 0) {
            for (index = 0; index < chunk; index++)
                destination[copied + index] = 0;
        } else {
            if (read_block(reader, disk_block) != 0)
                return -1;
            for (index = 0; index < chunk; index++)
                destination[copied + index] =
                    reader->scratch[block_offset + index];
        }
        copied += chunk;
    }
    return (ssize_t)copied;
}

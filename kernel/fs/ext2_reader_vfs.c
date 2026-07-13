/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/fs/ext2_reader_vfs.c
 * Layer: Kernel / read-only filesystem adapter
 *
 * Responsibilities:
 * - Adapt path-based ext2 reader operations to common VFS inode/file methods.
 * - Supply lookup, read, seek and directory iteration for bring-up roots.
 * - Keep syscall and descriptor semantics in the common VFS layer.
 *
 * Notes:
 * - Operations tables are populated at runtime so high-alias kernels do not
 *   retain physical-link-address function pointers after retiring low maps.
 */

#include <kernel/ext2_reader_vfs.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/vfs.h>

typedef struct ext2_reader_vfs_node {
    ext2_reader_t *reader;
    char path[MAX_PATH];
} ext2_reader_vfs_node_t;

static file_operations_t reader_file_ops;
static file_operations_t reader_dir_ops;
static inode_operations_t reader_inode_ops;
static bool reader_ops_ready;

static void release_node(inode_t *inode)
{
    if (inode && inode->private_data) {
        kfree(inode->private_data);
        inode->private_data = NULL;
    }
}

static void destroy_unpublished_inode(inode_t *inode)
{
    if (!inode)
        return;
    release_node(inode);
    kfree(inode);
}

static inode_t *make_inode(ext2_reader_t *reader, const char *path,
                           const ext2_reader_path_info_t *info)
{
    ext2_reader_vfs_node_t *node;
    inode_t *inode;

    if (!reader || !path || !info)
        return NULL;
    inode = kmalloc(sizeof(*inode));
    node = kmalloc(sizeof(*node));
    if (!inode || !node) {
        kfree(node);
        kfree(inode);
        return NULL;
    }
    memset(inode, 0, sizeof(*inode));
    memset(node, 0, sizeof(*node));
    node->reader = reader;
    strncpy(node->path, path, sizeof(node->path) - 1u);
    inode->ino = info->inode;
    inode->first_cluster = info->inode;
    inode->mode = info->type == EXT2_READER_PATH_DIRECTORY ?
        (S_IFDIR | 0555) : (S_IFREG | 0444);
    inode->size = (uint32_t)info->size;
    inode->nlink = 1;
    inode->ref_count = 1;
    inode->i_op = &reader_inode_ops;
    inode->f_op = info->type == EXT2_READER_PATH_DIRECTORY ?
        &reader_dir_ops : &reader_file_ops;
    inode->private_data = node;
    inode->release_private = release_node;
    return inode;
}

static inode_t *reader_lookup(inode_t *directory, const char *name)
{
    ext2_reader_vfs_node_t *parent;
    ext2_reader_path_info_t info;
    char path[MAX_PATH];
    size_t length;

    if (!directory || !name || !S_ISDIR(directory->mode))
        return NULL;
    parent = directory->private_data;
    if (!parent || !parent->reader)
        return NULL;
    length = strlen(parent->path);
    if (strcmp(parent->path, "/") == 0)
        snprintf(path, sizeof(path), "/%s", name);
    else
        snprintf(path, sizeof(path), "%s/%s", parent->path, name);
    if (length + strlen(name) + 2u > sizeof(path) ||
        ext2_reader_path_info(parent->reader, path, &info) != 0)
        return NULL;
    return make_inode(parent->reader, path, &info);
}

static int reader_open(inode_t *inode, file_t *file)
{
    if (!inode || !file)
        return -EINVAL;
    file->f_op = inode->f_op;
    return 0;
}

static int reader_close(file_t *file)
{
    (void)file;
    return 0;
}

static ssize_t reader_read(file_t *file, void *buffer, size_t count)
{
    ext2_reader_vfs_node_t *node;
    ssize_t result;

    if (!file || !file->inode || !buffer)
        return -EINVAL;
    node = file->inode->private_data;
    if (!node || !node->reader)
        return -EIO;
    result = ext2_reader_read_range(node->reader, node->path,
                                    file->offset, buffer, count);
    if (result > 0)
        file->offset += (uint32_t)result;
    return result;
}

static off_t reader_lseek(file_t *file, off_t offset, int whence)
{
    off_t base;
    off_t target;

    if (!file || !file->inode)
        return -EINVAL;
    if (whence == SEEK_SET)
        base = 0;
    else if (whence == SEEK_CUR)
        base = (off_t)file->offset;
    else if (whence == SEEK_END)
        base = (off_t)file->inode->size;
    else
        return -EINVAL;
    target = base + offset;
    if (target < 0 || (uint64_t)target > file->inode->size)
        return -EINVAL;
    file->offset = (uint32_t)target;
    return target;
}

static int reader_readdir(file_t *file, dirent_t *dirent)
{
    ext2_reader_vfs_node_t *node;
    ext2_reader_dir_entry_t entry;
    size_t offset;
    int result;

    if (!file || !file->inode || !dirent)
        return -EINVAL;
    node = file->inode->private_data;
    if (!node || !node->reader)
        return -EIO;
    offset = file->offset;
    result = ext2_reader_read_directory(node->reader, node->path,
                                        &offset, &entry);
    if (result <= 0)
        return result;
    memset(dirent, 0, sizeof(*dirent));
    dirent->d_ino = entry.inode;
    dirent->d_reclen = sizeof(*dirent);
    dirent->d_type = entry.type == EXT2_READER_PATH_DIRECTORY ?
        DT_DIR : DT_REG;
    strncpy(dirent->d_name, entry.name, sizeof(dirent->d_name) - 1u);
    file->offset = (uint32_t)offset;
    return 1;
}

static void initialize_operations(void)
{
    if (reader_ops_ready)
        return;
    memset(&reader_file_ops, 0, sizeof(reader_file_ops));
    memset(&reader_dir_ops, 0, sizeof(reader_dir_ops));
    memset(&reader_inode_ops, 0, sizeof(reader_inode_ops));
    reader_file_ops.read = reader_read;
    reader_file_ops.open = reader_open;
    reader_file_ops.close = reader_close;
    reader_file_ops.lseek = reader_lseek;
    reader_dir_ops.open = reader_open;
    reader_dir_ops.close = reader_close;
    reader_dir_ops.readdir = reader_readdir;
    reader_inode_ops.lookup = reader_lookup;
    reader_ops_ready = true;
}

bool ext2_reader_vfs_mount_root(ext2_reader_t *reader)
{
    ext2_reader_path_info_t info;
    inode_t *root;

    initialize_operations();
    if (!reader || ext2_reader_path_info(reader, "/", &info) != 0 ||
        info.type != EXT2_READER_PATH_DIRECTORY)
        return false;
    root = make_inode(reader, "/", &info);
    if (!root)
        return false;
    if (!vfs_install_root(root)) {
        destroy_unpublished_inode(root);
        return false;
    }
    return true;
}

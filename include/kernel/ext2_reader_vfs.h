/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/ext2_reader_vfs.h
 * Layer: Kernel / read-only filesystem adapter
 *
 * Responsibilities:
 * - Expose the early ext2 reader through standard ArmOS VFS inode operations.
 * - Install a read-only root usable by the common file syscalls.
 *
 * Notes:
 * - This adapter is architecture-neutral and intentionally read-only.
 */

#ifndef _KERNEL_EXT2_READER_VFS_H
#define _KERNEL_EXT2_READER_VFS_H

#include <kernel/ext2_reader.h>
#include <kernel/types.h>

bool ext2_reader_vfs_mount_root(ext2_reader_t *reader);

#endif /* _KERNEL_EXT2_READER_VFS_H */

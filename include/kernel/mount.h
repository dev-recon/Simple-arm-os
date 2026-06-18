#ifndef _KERNEL_MOUNT_H
#define _KERNEL_MOUNT_H

#include <kernel/disk_layout.h>

#define FSTAB_PATH "/etc/fstab"

int vfs_mount_from_fstab(const char* path);
int vfs_mount_fat32_partition(const disk_partition_t* part);
int vfs_mount_user(const char* source, const char* target, const char* fstype,
                   uint32_t flags, const void* data);

#endif

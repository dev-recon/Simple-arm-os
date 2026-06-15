#ifndef _KERNEL_MOUNT_H
#define _KERNEL_MOUNT_H

#include <kernel/disk_layout.h>

#define FSTAB_PATH "/etc/fstab"

int vfs_mount_from_fstab(const char* path);
int vfs_mount_fat32_partition(const disk_partition_t* part);

#endif

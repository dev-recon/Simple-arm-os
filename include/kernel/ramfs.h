/* kernel/include/kernel/ramfs.h - RAMFS Header */
#ifndef _KERNEL_RAMFS_H
#define _KERNEL_RAMFS_H

#include <kernel/types.h>
#include <kernel/spinlock.h>

/* RAMFS Device Structure */
typedef struct {
    uint8_t* memory_base;           /* Base address of RAM disk */
    uint32_t total_size;            /* Total size in bytes */
    uint32_t sector_size;           /* Sector size (512) */
    uint32_t total_sectors;         /* Total sectors */
    bool initialized;               /* Initialization status */
    spinlock_t lock;               /* Access synchronization */
} ramfs_device_t;


/* RAMFS API - Compatible avec ATA */
bool init_ramfs(void);
bool ramfs_is_initialized(void);
uint64_t ramfs_get_capacity_sectors(void);
uint32_t ramfs_get_sector_size(void);
bool ramfs_is_ready(void);

/* I/O Operations */
int ramfs_read_sectors(uint64_t lba, uint32_t count, void* buffer);
int ramfs_write_sectors(uint64_t lba, uint32_t count, const void* buffer);

void create_fat32_boot_sector(void);
void create_fat32_fat_tables(void);
void create_fat32_root_directory(void);

/* Test function */
void ramfs_test(void);
void ramfs_tar_test(void);

#endif /* _KERNEL_RAMFS_H */
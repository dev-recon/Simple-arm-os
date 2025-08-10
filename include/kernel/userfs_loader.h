/* userfs_loader.h - Load userfs from memory */
#ifndef USERFS_LOADER_H
#define USERFS_LOADER_H

#include <kernel/types.h>

/*#define USERFS_MAGIC (((uint64_t)'U' << 0) | ((uint64_t)'S' << 8) | \
//                     ((uint64_t)'E' << 16) | ((uint64_t)'R' << 24) | \
//                     ((uint64_t)'F' << 32) | ((uint64_t)'S' << 40) | \
//                     ((uint64_t)'0' << 48) | ((uint64_t)'1' << 56)) */

//#define USERFS_LOAD_ADDR  0x41000000              /* QEMU loader address */
#define USERFS_LOAD_ADDR  0x50000000              /* QEMU loader address */

typedef struct {
    uint64_t magic;      /* Magic signature */
    uint32_t size;       /* TAR data size */
    uint8_t data[];      /* TAR data */
} __attribute__((packed)) userfs_header_t;

/* Function to load userfs from memory */
bool load_userfs_from_memory2(void);
void extract_userfs_to_ramfs(const uint8_t* tar_data, uint32_t size);

#endif /* USERFS_LOADER_H */
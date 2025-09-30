/* include/kernel/fat32.h */
#ifndef _KERNEL_FAT32_H
#define _KERNEL_FAT32_H

#include <kernel/types.h>
#include <kernel/file.h>

#define FAT32_SECTOR_SIZE   512
#define FAT32_MAX_FILENAME  255

/* FAT32 Boot Sector - VERSION ALIGNeE POUR ARM32 */
typedef struct __attribute__((packed)) {
    uint8_t data[512];
} fat32_raw_sector_t;

/* CORRECTION 1: fat32_boot_sector_t SANS PADDING */
typedef struct {
    /* 0x00-0x0A: Header exact */
    uint8_t jump[3];                    /* 0x00: Jump instruction */
    char oem_name[8];                   /* 0x03: OEM name */
    
    /* 0x0B-0x23: BIOS Parameter Block - OFFSETS EXACTS FAT32 */
    uint16_t bytes_per_sector;          /* 0x0B: Bytes per sector OK */
    uint8_t sectors_per_cluster;        /* 0x0D: Sectors per cluster OK */
    uint16_t reserved_sectors;          /* 0x0E: Reserved sectors OK */
    uint8_t num_fats;                   /* 0x10: Number of FATs OK */
    uint16_t root_entries;              /* 0x11: Root entries OK */
    uint16_t total_sectors_16;          /* 0x13: Total sectors 16-bit OK */
    uint8_t media_type;                 /* 0x15: Media descriptor OK */
    uint16_t fat_size_16;               /* 0x16: FAT size 16-bit OK */
    uint16_t sectors_per_track;         /* 0x18: Sectors per track OK */
    uint16_t num_heads;                 /* 0x1A: Number of heads OK */
    uint32_t hidden_sectors;            /* 0x1C: Hidden sectors OK */
    uint32_t total_sectors_32;          /* 0x20: Total sectors 32-bit OK */
    
    /* 0x24-0x51: FAT32 Extended BPB */
    uint32_t fat_size_32;               /* 0x24: FAT size 32-bit OK */
    uint16_t ext_flags;                 /* 0x28: Extended flags OK */
    uint16_t fs_version;                /* 0x2A: Filesystem version OK */
    uint32_t root_cluster;              /* 0x2C: Root cluster OK */
    uint16_t fs_info;                   /* 0x30: FSInfo sector OK */
    uint16_t backup_boot;               /* 0x32: Backup boot sector OK */
    uint8_t reserved[12];               /* 0x34: Reserved OK */
    uint8_t drive_number;               /* 0x40: Drive number OK */
    uint8_t reserved1;                  /* 0x41: Reserved OK */
    uint8_t boot_signature;             /* 0x42: Boot signature OK */
    uint32_t volume_id;                 /* 0x43: Volume ID OK */
    char volume_label[11];              /* 0x47: Volume label OK */
    char fs_type[8];                    /* 0x52: Filesystem type OK */
    
    /* 0x5A-0x1FF: Boot code et signature */
    uint8_t boot_code[420];             /* 0x5A: Boot code */
    uint16_t boot_signature_55aa;       /* 0x1FE: Boot signature 0x55AA OK */
    
} __attribute__((packed)) fat32_boot_sector_t;


/* FAT32 Directory Entry - ALIGNeE */
typedef struct {
    char name[11];                      /* 0x00: 8.3 filename */
    uint8_t attr;                       /* 0x0B: Attributes */
    uint8_t nt_reserved;                /* 0x0C: NT reserved */
    uint8_t create_time_tenth;          /* 0x0D: Create time (tenths) */
    uint16_t create_time;               /* 0x0E: Create time OK */
    uint16_t create_date;               /* 0x10: Create date OK */
    uint16_t last_access_date;          /* 0x12: Last access date OK */
    uint16_t first_cluster_hi;          /* 0x14: First cluster (high) OK */
    uint16_t write_time;                /* 0x16: Write time OK */
    uint16_t write_date;                /* 0x18: Write date OK */
    uint16_t first_cluster_lo;          /* 0x1A: First cluster (low) OK */
    uint32_t file_size;                 /* 0x1C: File size OK */
} __attribute__((packed)) fat32_dir_entry_t;

/* Long Filename Entry - ALIGNeE */
typedef struct {
    uint8_t order;                      /* 0x00: Order */
    uint16_t name1[5];                  /* 0x01: Name chars 1-5 OK */
    uint8_t attr;                       /* 0x0B: Attributes (always 0x0F) */
    uint8_t type;                       /* 0x0C: Type */
    uint8_t checksum;                   /* 0x0D: Checksum */
    uint16_t name2[6];                  /* 0x0E: Name chars 6-11 OK */
    uint16_t first_cluster;             /* 0x1A: First cluster (always 0) */
    uint16_t name3[2];                  /* 0x1C: Name chars 12-13 OK */
} __attribute__((packed)) fat32_lfn_entry_t;

/* Attributes */
#define FAT_ATTR_READ_ONLY  0x01
#define FAT_ATTR_HIDDEN     0x02
#define FAT_ATTR_SYSTEM     0x04
#define FAT_ATTR_VOLUME_ID  0x08
#define FAT_ATTR_DIRECTORY  0x10
#define FAT_ATTR_ARCHIVE    0x20
#define FAT_ATTR_LFN        0x0F

#define FAT32_EOC           0x0FFFFFF8
#define FAT32_BAD_CLUSTER   0x0FFFFFF7
#define FAT32_FREE_CLUSTER  0x00000000

/* Caractères spéciaux dans les noms */
#define FAT32_DELETED_ENTRY     0xE5    /* Entrée supprimée */
#define FAT32_END_OF_ENTRIES    0x00    /* Fin des entrées */

/* Masques utiles */
#define FAT32_ATTR_LONG_NAME_MASK   0x0F
#define FAT32_ATTR_ALL             0x3F

#define FAT32_ATTR_LONG_NAME FAT_ATTR_LFN


/* Macro pour détecter les entrées Long File Name (LFN) */
#define IS_LONG_NAME(attr)      (((attr) & FAT32_ATTR_LONG_NAME_MASK) == FAT32_ATTR_LONG_NAME)

/* Structure principale du filesystem - ALIGNeE */
typedef struct {
    //fat32_boot_sector_t boot_sector __attribute__((aligned(4)));
    fat32_boot_sector_t boot_sector;
    
    /* Champs 4 bytes groupes pour alignement */
    uint32_t* fat_table;                /* 4 bytes */
    uint32_t fat_start_sector;          /* 4 bytes */
    uint32_t data_start_sector;         /* 4 bytes */
    uint32_t root_dir_cluster;          /* 4 bytes */
    uint32_t sectors_per_cluster;       /* 4 bytes */
    uint32_t bytes_per_cluster;         /* 4 bytes */
    
    /* Boolean et padding */
    bool mounted;                       /* 1 byte */
    uint8_t padding[3];                 /* 3 bytes pour aligner sur 4 */
} __attribute__((aligned(8))) fat32_fs_t;


int init_fat32(void);
int mount_fat32_filesystem(void);

/* FAT32 functions - INCHANGeES */
bool fat32_mount(void);
uint32_t get_fat32_root_cluster(void);
uint32_t cluster_to_sector(uint32_t cluster);
uint32_t fat32_get_next_cluster(uint32_t cluster);
int fat32_read_cluster(uint32_t cluster, void* buffer);
int fat32_read_file(uint32_t first_cluster, uint32_t file_size, void* buffer);
fat32_dir_entry_t* fat32_find_file(uint32_t dir_cluster, const char* filename);
void fat32_83_to_name(const char* fat_name, char* output);
uint32_t fat32_date_to_unix(uint16_t fat_date, uint16_t fat_time);
//int fat32_file_exists_in_dir(inode_t* dir_inode, const char* filename);
//inode_t* fat32_create_file(const char* parent_path, const char* filename, mode_t mode);

/* Nouvelles fonctions pour acceder aux informations du filesystem */
uint32_t get_fat32_bytes_per_cluster(void);
uint32_t get_fat32_sectors_per_cluster(void);
bool is_fat32_mounted(void);

/* Macro pour verifier l'alignement des structures au compile-time */
#define CHECK_FAT32_ALIGNMENT() do { \
    _Static_assert(sizeof(fat32_boot_sector_t) % 4 == 0, "fat32_boot_sector_t not 4-byte aligned"); \
    _Static_assert(sizeof(fat32_dir_entry_t) % 4 == 0, "fat32_dir_entry_t not 4-byte aligned"); \
    _Static_assert(sizeof(fat32_lfn_entry_t) % 4 == 0, "fat32_lfn_entry_t not 4-byte aligned"); \
    _Static_assert(sizeof(fat32_fs_t) % 8 == 0, "fat32_fs_t not 8-byte aligned"); \
} while(0)

/* Fonction pour verifier l'alignement au runtime */
static inline void verify_fat32_alignment(void)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("[FAT32] Structure alignment verification:\n");
    kprintf("  fat32_boot_sector_t: size=%u, align=%u\n", 
            sizeof(fat32_boot_sector_t), __alignof__(fat32_boot_sector_t));
    kprintf("  fat32_dir_entry_t: size=%u, align=%u\n", 
            sizeof(fat32_dir_entry_t), __alignof__(fat32_dir_entry_t));
    kprintf("  fat32_fs_t: size=%u, align=%u\n", 
            sizeof(fat32_fs_t), __alignof__(fat32_fs_t));
    
    if (__alignof__(fat32_boot_sector_t) >= 4) {
        kprintf("  OK All FAT32 structures properly aligned\n");
    } else {
        kprintf("  KO FAT32 structures alignment issue!\n");
    }
}

#endif /* _KERNEL_FAT32_H */
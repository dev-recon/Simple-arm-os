/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/fs/fat32.c
 * Layer: Kernel / VFS and filesystems
 *
 * Responsibilities:
 * - Provide filesystem-independent VFS operations.
 * - Implement persistent ext2/FAT32/procfs behavior.
 *
 * Notes:
 * - Keep file descriptor and inode ownership rules explicit.
 */

#include <kernel/fat32.h>
#include <kernel/config.h>
#include <kernel/block_device.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>


#define storage_read_sectors(lba, count, buffer) blk_read_sectors(lba, count, buffer)
#define storage_write_sectors(lba, count, buffer) blk_write_sectors(lba, count, buffer)
#define storage_is_initialized() blk_is_initialized()


fat32_fs_t fat32_fs = {0};

extern bool is_fat_dirty(void);
extern bool is_dirty_inodes(void);
extern int sync_fat_to_disk(void);
extern void sync_dirty_inodes(void);
extern uint32_t fat32_get_total_clusters(void);

/* Utiliser un buffer aligne pour etre s-r */
//static uint8_t boot_buffer[516] __attribute__((aligned(8)));

static uint16_t read_le16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}


void fat32_parse_boot_sector(fat32_boot_sector_t* dst, const fat32_raw_sector_t* raw)
{
    const uint8_t* src = raw->data;

    KDEBUG("fat32_parse_boot_sector(): dst = %p, raw = %p\n", dst, raw);
    KDEBUG("raw->data = %p\n", raw->data);

    memcpy(dst->jump,         src + 0x00, 3);
    KDEBUG("dst->jump = %p\n", dst->jump);
    
    memcpy(dst->oem_name,     src + 0x03, 8);
    KDEBUG("dst->oem_name = %p\n", dst->oem_name);

    KDEBUG("Adresse bytes_per_sector = 0x%08X\n", (uint32_t)(src + 0x0B));
    dst->bytes_per_sector     = read_le16(src + 0x0B);

    dst->sectors_per_cluster  = src[0x0D];
    dst->reserved_sectors     = read_le16(src + 0x0E);
    dst->num_fats             = src[0x10];
    dst->root_entries         = read_le16(src + 0x11);
    dst->total_sectors_16     = read_le16(src + 0x13);
    dst->media_type           = src[0x15];
    dst->fat_size_16          = read_le16(src + 0x16);
    dst->sectors_per_track    = read_le16(src + 0x18);
    dst->num_heads            = read_le16(src + 0x1A);
    dst->hidden_sectors       = read_le32(src + 0x1C);
    dst->total_sectors_32     = read_le32(src + 0x20);

    dst->fat_size_32          = read_le32(src + 0x24);
    dst->ext_flags            = read_le16(src + 0x28);
    dst->fs_version           = read_le16(src + 0x2A);
    dst->root_cluster         = read_le32(src + 0x2C);
    dst->fs_info              = read_le16(src + 0x30);
    dst->backup_boot          = read_le16(src + 0x32);
    memcpy(dst->reserved,     src + 0x34, 12);
    dst->drive_number         = src[0x40];
    dst->reserved1            = src[0x41];
    dst->boot_signature       = src[0x42];
    dst->volume_id            = read_le32(src + 0x43);
    memcpy(dst->volume_label, src + 0x47, 11);
    memcpy(dst->fs_type,      src + 0x52, 8);
    memcpy(dst->boot_code,    src + 0x5A, 420);
    dst->boot_signature_55aa  = read_le16(src + 0x1FE);
}



extern int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer);
extern int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer);

bool fat32_mount(void)
{
    return fat32_mount_at(0);
}

bool fat32_mount_at(uint64_t lba_start){

    KDEBUG("Mounting FAT32 from active block device at LBA %u...\n",
           (uint32_t)lba_start);
    
    if (!blk_is_initialized() || blk_get_sector_size() != FAT32_SECTOR_SIZE) {
        KERROR("FAT32: block device not ready or invalid sector size (%u)\n",
               blk_get_sector_size());
        return false;
    }

    /* Allouer les structures */
    fat32_boot_sector_t *bs = kmalloc(sizeof(fat32_boot_sector_t));
    if (!bs) {
        KERROR("Failed to allocate boot sector\n");
        return false;
    }
    
    fat32_raw_sector_t *raw = kmalloc(sizeof(fat32_raw_sector_t));
    if (!raw) {
        KERROR("Failed to allocate raw sector\n");
        kfree(bs);
        return false;
    }
    
    /* Lire le boot sector depuis le debut de la partition FAT32 */
    KDEBUG("Reading FAT32 boot sector from LBA %u...\n",
           (uint32_t)lba_start);
    if (blk_read_sectors(lba_start, 1, raw->data) < 0) {
        KERROR("Failed to read FAT32 boot sector\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    /* Parser le boot sector */
    //fat32_parse_boot_sector(bs, raw);

    fat32_parse_boot_sector(&fat32_fs.boot_sector, raw);

    
    /* CORRECTION: Verifier que c'est bien du FAT32 */
    if (fat32_fs.boot_sector.boot_signature_55aa != 0xAA55) {
        KERROR("Invalid boot signature: 0x%04X\n", fat32_fs.boot_sector.boot_signature_55aa);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    if (fat32_fs.boot_sector.fat_size_32 == 0) {
        KERROR("Not a FAT32 filesystem (fat_size_32 = 0)\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    KINFO("FAT32 boot sector valid:\n");
    KINFO("  OEM: '%.8s'\n", fat32_fs.boot_sector.oem_name);
    KINFO("  Bytes/sector: %u\n", fat32_fs.boot_sector.bytes_per_sector);
    KINFO("  Sectors/cluster: %u\n", fat32_fs.boot_sector.sectors_per_cluster);
    KINFO("  Reserved sectors: %u\n", fat32_fs.boot_sector.reserved_sectors);
    KINFO("  FAT size: %u sectors\n", fat32_fs.boot_sector.fat_size_32);
    KINFO("  Root cluster: %u\n", fat32_fs.boot_sector.root_cluster);
    
    /* Calculer les secteurs absolus dans le disque. */
    fat32_fs.lba_start = lba_start;
    fat32_fs.fat_start_sector = (uint32_t)(lba_start + fat32_fs.boot_sector.reserved_sectors);
    fat32_fs.data_start_sector = (uint32_t)(lba_start + fat32_fs.boot_sector.reserved_sectors + (fat32_fs.boot_sector.num_fats * fat32_fs.boot_sector.fat_size_32));
    fat32_fs.root_dir_cluster = fat32_fs.boot_sector.root_cluster;
    fat32_fs.sectors_per_cluster = fat32_fs.boot_sector.sectors_per_cluster;
    fat32_fs.bytes_per_cluster = fat32_fs.boot_sector.sectors_per_cluster * fat32_fs.boot_sector.bytes_per_sector;
    
    KINFO("FAT32 layout calculated:\n");
    KINFO("  LBA start: sector %u\n", (uint32_t)fat32_fs.lba_start);
    KINFO("  FAT start: sector %u\n", fat32_fs.fat_start_sector);
    KINFO("  Data start: sector %u\n", fat32_fs.data_start_sector);
    KINFO("  Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("  Cluster size: %u bytes\n", fat32_fs.bytes_per_cluster);
    
    /* Charger la table FAT */
    uint32_t fat_size_bytes = fat32_fs.boot_sector.fat_size_32 * 512;
    fat32_fs.fat_table = (uint32_t *)kmalloc(fat_size_bytes);
    if (!fat32_fs.fat_table) {
        KERROR("Failed to allocate FAT table (%u bytes)\n", fat_size_bytes);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    KDEBUG("Reading FAT table from sector %u (%u sectors)...\n", 
           fat32_fs.fat_start_sector, fat32_fs.boot_sector.fat_size_32);
    
    if (blk_read_sectors(fat32_fs.fat_start_sector, fat32_fs.boot_sector.fat_size_32, fat32_fs.fat_table) < 0) {
        KERROR("Failed to read FAT table\n");
        kfree(fat32_fs.fat_table);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    /* CORRECTION: Test du root cluster */
    uint32_t root_sector = cluster_to_sector(fat32_fs.root_dir_cluster);
    KINFO("Testing root directory at cluster %u (sector %u)...\n", 
          fat32_fs.root_dir_cluster, root_sector);
    
    uint8_t test_buffer[512];
    if (blk_read_sectors(root_sector, 1, test_buffer) < 0) {
        KERROR("Cannot read root directory sector\n");
        kfree(fat32_fs.fat_table);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    /* Analyser la premiere entree du root directory */
    fat32_dir_entry_t* first_entry = (fat32_dir_entry_t*)test_buffer;
    if (first_entry->name[0] != 0) {
        KINFO("Root directory contains entries OK\n");
        
        /* Afficher les premieres entrees */
        for (int i = 0; i < 4; i++) {
            fat32_dir_entry_t* entry = &((fat32_dir_entry_t*)test_buffer)[i];
            if (entry->name[0] == 0) break;
            if (entry->name[0] == 0xE5) continue;
            
            char name[13];
            fat32_83_to_name((char*)entry->name, name);
            const char* type = (entry->attr & FAT_ATTR_DIRECTORY) ? "DIR" : "FILE";
            
            KINFO("  %s: %s (cluster %u)\n", type, name, 
                  (entry->first_cluster_hi << 16) | entry->first_cluster_lo);
        }
    } else {
        KWARN("Root directory appears empty\n");
    }
    
    fat32_fs.mounted = true;
    
    KINFO("FAT32 mount successful! OK\n");
    
    kfree(bs);
    kfree(raw);
    return true;

}


uint32_t get_fat32_root_cluster(void)
{
    return fat32_fs.root_dir_cluster;
}

uint32_t cluster_to_sector(uint32_t cluster)
{
    if (cluster < 2) return 0;
    return fat32_fs.data_start_sector + (cluster - 2) * fat32_fs.sectors_per_cluster;
}

uint32_t fat32_get_next_cluster(uint32_t cluster)
{
    if (cluster < 2 || cluster >= fat32_get_total_clusters()) {
        return FAT32_BAD_CLUSTER;  /* 0x0FFFFFF7 */
    }
    
    uint32_t next = fat32_fs.fat_table[cluster] & 0x0FFFFFFF;
    
    /* Retourner tel quel - l'appelant teste si >= FAT32_EOC */
    return next;
}

uint32_t fat32_get_next_cluster2(uint32_t cluster)
{
    uint32_t next;
    
    if (cluster >= 0x0FFFFFF8) return 0;
    
    next = fat32_fs.fat_table[cluster] & 0x0FFFFFFF;
    return (next >= 0x0FFFFFF8) ? 0 : next;
}

int fat32_read_cluster(uint32_t cluster, void* buffer)
{
    uint32_t sector;
    
    if (!fat32_fs.mounted || cluster < 2) return -1;
    
    sector = cluster_to_sector(cluster);
    return storage_read_sectors(sector, fat32_fs.sectors_per_cluster, buffer);
}


int fat32_read_file(uint32_t first_cluster, uint32_t file_size, void* buffer)
{
    uint32_t cluster = first_cluster;
    uint32_t bytes_read = 0;
    char* buf = (char*)buffer;
    void* cluster_buf;
    uint32_t bytes_to_copy;

    if( is_dirty_inodes() ){
        sync_dirty_inodes();
    }

    if( is_fat_dirty() )
    {
        sync_fat_to_disk();
    }
    
    while (cluster && cluster < 0x0FFFFFF8 && bytes_read < file_size) {
        cluster_buf = kmalloc(fat32_fs.bytes_per_cluster);
        if (!cluster_buf) return -1;
        
        if (fat32_read_cluster(cluster, cluster_buf) < 0) {
            kfree(cluster_buf);
            return -1;
        }
        
        bytes_to_copy = MIN(fat32_fs.bytes_per_cluster, file_size - bytes_read);
        memcpy(buf + bytes_read, cluster_buf, bytes_to_copy);
        bytes_read += bytes_to_copy;
        
        kfree(cluster_buf);
        cluster = fat32_get_next_cluster(cluster);
    }
    
    return bytes_read;
}


fat32_dir_entry_t* fat32_find_file(uint32_t dir_cluster, const char* filename)
{
    uint32_t cluster = dir_cluster;
    void* cluster_buf;
    fat32_dir_entry_t* entries;
    uint32_t entries_per_cluster;
    uint32_t i;
    fat32_dir_entry_t* entry;
    char entry_name[13];
    fat32_dir_entry_t* result;
    char lfn_name[FAT32_MAX_FILENAME + 1];
    uint8_t lfn_checksum = 0;
    bool lfn_pending = false;


    if( is_dirty_inodes() ){
        sync_dirty_inodes();
    }
    
    if( is_fat_dirty() )
    {
        sync_fat_to_disk();
    }
    
    while (cluster && cluster < 0x0FFFFFF8) {
        cluster_buf = kmalloc(fat32_fs.bytes_per_cluster);
        if (!cluster_buf) return NULL;
        
        if (fat32_read_cluster(cluster, cluster_buf) < 0) {
            kfree(cluster_buf);
            return NULL;
        }
        
        entries = (fat32_dir_entry_t*)cluster_buf;
        entries_per_cluster = fat32_fs.bytes_per_cluster / sizeof(fat32_dir_entry_t);
        
        for (i = 0; i < entries_per_cluster; i++) {
            entry = &entries[i];
            
            /* End of directory */
            if (entry->name[0] == 0) {
                kfree(cluster_buf);
                return NULL;
            }
            
            /* Deleted entry */
            if (entry->name[0] == 0xE5) {
                lfn_pending = false;
                fat32_lfn_clear(lfn_name, sizeof(lfn_name));
                continue;
            }
            
            /* LFN entry */
            if (IS_LONG_NAME(entry->attr)) {
                fat32_lfn_entry_t* lfn = (fat32_lfn_entry_t*)entry;

                if (lfn->order & 0x40) {
                    fat32_lfn_clear(lfn_name, sizeof(lfn_name));
                    lfn_checksum = lfn->checksum;
                    lfn_pending = true;
                }

                if (lfn_pending &&
                    lfn->checksum == lfn_checksum &&
                    fat32_lfn_decode_entry(lfn, lfn_name, sizeof(lfn_name)) == 0) {
                    continue;
                }

                lfn_pending = false;
                fat32_lfn_clear(lfn_name, sizeof(lfn_name));
                continue;
            }

            if (entry->attr & FAT_ATTR_VOLUME_ID) {
                lfn_pending = false;
                fat32_lfn_clear(lfn_name, sizeof(lfn_name));
                continue;
            }
            
            /* Convert name and compare */
            fat32_83_to_name(entry->name, entry_name);
            
            if ((lfn_pending &&
                 fat32_lfn_matches_short(lfn_name, lfn_checksum, entry) &&
                 fat32_name_equals(lfn_name, filename)) ||
                fat32_name_equals(entry_name, filename)) {
                result = kmalloc(sizeof(fat32_dir_entry_t));
                if (result) {
                    memcpy(result, entry, sizeof(fat32_dir_entry_t));
                }
                kfree(cluster_buf);
                return result;
            }

            lfn_pending = false;
            fat32_lfn_clear(lfn_name, sizeof(lfn_name));
        }
        
        kfree(cluster_buf);
        cluster = fat32_get_next_cluster(cluster);
    }
    
    return NULL;
}

uint8_t fat32_lfn_checksum(const char fat_name[11])
{
    uint8_t sum = 0;

    for (int i = 0; i < 11; i++) {
        sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + (uint8_t)fat_name[i];
    }

    return sum;
}

void fat32_lfn_clear(char* lfn, size_t len)
{
    if (!lfn || len == 0) return;
    memset(lfn, 0, len);
}

static void fat32_lfn_store_char(char* lfn, size_t len, size_t pos, uint16_t ch)
{
    if (!lfn || pos >= len - 1) return;

    if (ch == 0x0000 || ch == 0xFFFF) {
        return;
    }

    lfn[pos] = (ch < 0x80) ? (char)ch : '?';
}

int fat32_lfn_decode_entry(const fat32_lfn_entry_t* entry, char* lfn, size_t len)
{
    uint8_t order;
    size_t pos;

    if (!entry || !lfn || len == 0 || entry->attr != FAT_ATTR_LFN ||
        entry->type != 0 || entry->first_cluster != 0) {
        return -EINVAL;
    }

    order = entry->order & 0x1F;
    if (order == 0) {
        return -EINVAL;
    }

    pos = (order - 1) * 13;
    if (pos >= len) {
        return -EINVAL;
    }

    for (int i = 0; i < 5; i++)
        fat32_lfn_store_char(lfn, len, pos++, entry->name1[i]);
    for (int i = 0; i < 6; i++)
        fat32_lfn_store_char(lfn, len, pos++, entry->name2[i]);
    for (int i = 0; i < 2; i++)
        fat32_lfn_store_char(lfn, len, pos++, entry->name3[i]);

    lfn[len - 1] = '\0';
    return 0;
}

bool fat32_lfn_matches_short(const char* lfn, uint8_t checksum, const fat32_dir_entry_t* entry)
{
    return lfn && lfn[0] != '\0' && entry &&
           checksum == fat32_lfn_checksum(entry->name);
}

bool fat32_name_equals(const char* a, const char* b)
{
    if (!a || !b) return false;

    while (*a && *b) {
        if (tolower(*a) != tolower(*b)) {
            return false;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

void fat32_83_to_name(const char* fat_name, char* output)
{
    int out_pos = 0;
    int i;
    
    /* Base name (8 chars max) */
    for (i = 0; i < 8 && fat_name[i] != ' '; i++) {
        output[out_pos++] = tolower(fat_name[i]);
    }
    
    /* Extension (3 chars max) */
    if (fat_name[8] != ' ') {
        output[out_pos++] = '.';
        for (i = 8; i < 11 && fat_name[i] != ' '; i++) {
            output[out_pos++] = tolower(fat_name[i]);
        }
    }
    
    output[out_pos] = 0;
}

uint32_t fat32_date_to_unix(uint16_t fat_date, uint16_t fat_time)
{
    int year = 1980 + ((fat_date >> 9) & 0x7F);
    int month = (fat_date >> 5) & 0x0F;
    int day = fat_date & 0x1F;
    int hour = (fat_time >> 11) & 0x1F;
    int minute = (fat_time >> 5) & 0x3F;
    int second = (fat_time & 0x1F) * 2;
    
    /* Simplified conversion */
    return (year - 1970) * 365 * 24 * 3600 + 
           month * 30 * 24 * 3600 + 
           day * 24 * 3600 + 
           hour * 3600 + 
           minute * 60 + 
           second;
}


uint32_t get_fat32_bytes_per_cluster(void)
{
    return fat32_fs.bytes_per_cluster;
}

uint32_t get_fat32_sectors_per_cluster(void)
{
    return fat32_fs.sectors_per_cluster;
}

bool is_fat32_mounted(void)
{
    return fat32_fs.mounted;
}



/**
 * Initialise FAT32 sans monter - juste preparer les structures
 */
int init_fat32(void)
{
    KINFO("[FAT32] Initialisation...\n");
    
    /* Verifier que le stockage est pret */
    if (!storage_is_initialized()) {
        KERROR("[FAT32] Stockage non initialise\n");
        return -1;
    }
    
    /* Initialiser la structure */
    memset(&fat32_fs, 0, sizeof(fat32_fs_t));
    
    KINFO("[FAT32] Pret pour montage\n");
    return 0;
}

/**
 * Mount the FAT32 filesystem from the active block device.
 */
int mount_fat32_filesystem(void)
{
    return mount_fat32_filesystem_at(0);
}

int mount_fat32_filesystem_at(uint64_t lba_start)
{
    KINFO("[FAT32] Mounting filesystem at LBA %u...\n",
          (uint32_t)lba_start);
    
    if (!fat32_mount_at(lba_start)) {
        KERROR("[FAT32] Mouting failed\n");
        return -1;
    }
    
    KINFO("[FAT32] Filesystem mounted successfully\n");
    KINFO("[FAT32]   Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("[FAT32]   Data start: secteur %u\n", fat32_fs.data_start_sector);
    KINFO("[FAT32]   Bytes per cluster: %u\n", fat32_fs.bytes_per_cluster);
    
    return 0;
}

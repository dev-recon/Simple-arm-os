#include <kernel/fat32.h>
#include <kernel/ata.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#ifdef USE_RAMFS
#include <kernel/ramfs.h>
#endif

#ifdef USE_RAMFS
    #define storage_read_sectors(lba, count, buffer) ramfs_read_sectors(lba, count, buffer)
    #define storage_write_sectors(lba, count, buffer) ramfs_write_sectors(lba, count, buffer)
    #define storage_is_initialized() ramfs_is_initialized()
#else
    #define storage_read_sectors(lba, count, buffer) ata_read_sectors(lba, count, buffer)
    #define storage_write_sectors(lba, count, buffer) ata_write_sectors(lba, count, buffer)
    #define storage_is_initialized() ata_is_initialized()
#endif

fat32_fs_t fat32_fs = {0};
bool test_ata_before_fat32(void) ;
int ata_read_sectors_debug(uint64_t lba, uint32_t count, void* buffer);
void fat32_parse_boot_sector_ultra_safe(fat32_boot_sector_t* dst, const fat32_raw_sector_t* raw);
void run_pointer_arithmetic_test(const fat32_raw_sector_t* raw) ;

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

int ata_read_sectors_debug(uint64_t lba, uint32_t count, void* buffer)
{
    KDEBUG("=== ATA READ DEBUG ===\n");
    KDEBUG("ata_read_sectors called:\n");
    KDEBUG("  LBA: %u\n", (uint32_t)lba);
    KDEBUG("  Count: %u\n", count);
    KDEBUG("  Buffer: %p\n", buffer);
    KDEBUG("  Device initialized: %s\n", ata_is_initialized() ? "YES" : "NO");
    KDEBUG("  Device capacity: %u sectors\n", (uint32_t)ata_get_capacity_sectors());
    
    if (!ata_is_initialized()) {
        KERROR("ATA: Device not initialized\n");
        return -1;
    }
    
    if (!buffer) {
        KERROR("ATA: Invalid buffer\n");
        return -1;
    }
    
    if (lba >= ata_get_capacity_sectors()) {
        KERROR("ATA: LBA %u >= capacity %u\n", (uint32_t)lba, (uint32_t)ata_get_capacity_sectors());
        return -1;
    }
    
    /* IMPORTANT: Votre ata_read_sectors actuel est probablement un STUB ! */
    /* Verifiez le code de ata_read_sectors() dans votre ata.c */
    
    KDEBUG("Calling real ata_read_sectors...\n");
    int result = ata_read_sectors(lba, count, buffer);
    KDEBUG("ata_read_sectors returned: %d\n", result);
    
    if (result > 0) {
        /* Analyser ce qui a ete lu */
        uint8_t* bytes = (uint8_t*)buffer;
        KDEBUG("First 32 bytes read:\n");
        KDEBUG("  ");
        for (int i = 0; i < 32; i++) {
            kprintf("%02X ", bytes[i]);
            if ((i + 1) % 16 == 0) {
                kprintf("\n");
                if (i < 31) KDEBUG("  ");
            }
        }
        kprintf("\n");
        
        /* Verifier si c'est tout zero */
        bool all_zero = true;
        for (int i = 0; i < 512; i++) {
            if (bytes[i] != 0) {
                all_zero = false;
                break;
            }
        }
        
        if (all_zero) {
            KERROR("ATA: Read returned all zeros - VirtIO read not working!\n");
        } else {
            KINFO("ATA: Read returned real data OK\n");
        }
    }
    
    KDEBUG("=== END ATA READ DEBUG ===\n");
    return result;
}

bool fat32_mount(){

    KDEBUG("Mounting FAT32 from RAMFS...\n");
    
    /* Verifier que RAMFS est initialise */
    if (!ramfs_is_initialized()) {
        KERROR("FAT32: RAMFS not initialized\n");
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
    
    /* Lire le boot sector depuis RAMFS */
    KDEBUG("Reading boot sector from RAMFS sector 0...\n");
    if (ramfs_read_sectors(0, 1, raw->data) < 0) {
        KERROR("Failed to read boot sector from RAMFS\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    /* Parser le boot sector */
    fat32_parse_boot_sector(bs, raw);
    
    /* CORRECTION: Verifier que c'est bien du FAT32 */
    if (bs->boot_signature_55aa != 0xAA55) {
        KERROR("Invalid boot signature: 0x%04X\n", bs->boot_signature_55aa);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    if (bs->fat_size_32 == 0) {
        KERROR("Not a FAT32 filesystem (fat_size_32 = 0)\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    KINFO("FAT32 boot sector valid:\n");
    KINFO("  OEM: '%.8s'\n", bs->oem_name);
    KINFO("  Bytes/sector: %u\n", bs->bytes_per_sector);
    KINFO("  Sectors/cluster: %u\n", bs->sectors_per_cluster);
    KINFO("  Reserved sectors: %u\n", bs->reserved_sectors);
    KINFO("  FAT size: %u sectors\n", bs->fat_size_32);
    KINFO("  Root cluster: %u\n", bs->root_cluster);
    
    /* CORRECTION: Calculer correctement les offsets */
    fat32_fs.fat_start_sector = bs->reserved_sectors;
    fat32_fs.data_start_sector = bs->reserved_sectors + (bs->num_fats * bs->fat_size_32);
    fat32_fs.root_dir_cluster = bs->root_cluster;
    fat32_fs.sectors_per_cluster = bs->sectors_per_cluster;
    fat32_fs.bytes_per_cluster = bs->sectors_per_cluster * bs->bytes_per_sector;
    
    KINFO("FAT32 layout calculated:\n");
    KINFO("  FAT start: sector %u\n", fat32_fs.fat_start_sector);
    KINFO("  Data start: sector %u\n", fat32_fs.data_start_sector);
    KINFO("  Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("  Cluster size: %u bytes\n", fat32_fs.bytes_per_cluster);
    
    /* Charger la table FAT */
    uint32_t fat_size_bytes = bs->fat_size_32 * 512;
    fat32_fs.fat_table = kmalloc(fat_size_bytes);
    if (!fat32_fs.fat_table) {
        KERROR("Failed to allocate FAT table (%u bytes)\n", fat_size_bytes);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    KDEBUG("Reading FAT table from sector %u (%u sectors)...\n", 
           fat32_fs.fat_start_sector, bs->fat_size_32);
    
    if (ramfs_read_sectors(fat32_fs.fat_start_sector, bs->fat_size_32, fat32_fs.fat_table) < 0) {
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
    if (ramfs_read_sectors(root_sector, 1, test_buffer) < 0) {
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

bool fat32_mount2(void)
{
    KDEBUG("Trying to mount FAT32....\n");

#ifdef USE_RAMFS
    KDEBUG("Using RAMFS instead of ATA for FAT32...\n");
    
    /* Verifier que RAMFS est initialise */
    if (!ramfs_is_initialized()) {
        KERROR("FAT32: RAMFS device not initialized\n");
        return false;
    }
    
    uint64_t capacity = ramfs_get_capacity_sectors();
    uint32_t sector_size = ramfs_get_sector_size();
    
    KINFO("FAT32: RAMFS device capacity: %u sectors (%u MB)\n",
          (uint32_t)capacity,
          (uint32_t)(capacity * sector_size / (1024*1024)));
    
    /* Pas besoin de diagnostic VirtIO avec RAMFS */
    
#else
    /* Code ATA/VirtIO original */
    // DIAGNOSTIC COMPLET
    virtio_comprehensive_test();
    
    KDEBUG("Trying true = VirtIO reel.     ....\n");
    // NOUVEAU: Choisir le mode 
    ata_set_real_mode(true);  // false = simulation, true = VirtIO reel

    /* Test 1: Verifier que l'ATA fonctionne */
    if (!ata_is_initialized()) {
        KERROR("FAT32: ATA device not initialized\n");
        return false;
    }
    
    uint64_t capacity = ata_get_capacity_sectors();
    uint32_t sector_size = ata_get_sector_size();
    
    KINFO("FAT32: ATA device capacity: %u sectors (%u MB)\n",
          (uint32_t)capacity,
          (uint32_t)(capacity * sector_size / (1024*1024)));
#endif

    uint32_t fat_sectors;

    // Allocations dynamiques
    fat32_boot_sector_t *bs = (fat32_boot_sector_t*)kmalloc(sizeof(fat32_boot_sector_t));
    if (!bs) {
        KERROR("Failed to allocate boot sector structure\n");
        return false;
    }

    fat32_raw_sector_t *raw = (fat32_raw_sector_t*)kmalloc(sizeof(fat32_raw_sector_t));
    if (!raw) {
        KERROR("Failed to allocate raw sector structure\n");
        kfree(bs);
        return false;
    }

    // Verification de l'alignement
    KDEBUG("=== ALIGNMENT CHECK ===\n");
    KDEBUG("bs address: %p (aligned: %s)\n", bs, ((uintptr_t)bs % 4 == 0) ? "YES" : "NO");
    KDEBUG("raw address: %p (aligned: %s)\n", raw, ((uintptr_t)raw % 4 == 0) ? "YES" : "NO");

    /* Lire le boot sector */
    KDEBUG("Reading boot sector from LBA 0...\n");
    
#ifdef USE_RAMFS
    if (ramfs_read_sectors(0, 1, raw->data) < 0) {
        KERROR("FAT32: Failed to read boot sector from RAMFS\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
#else
    if (ata_read_sectors(0, 1, raw->data) < 0) {
        KERROR("FAT32: Failed to read boot sector from ATA\n");
        kfree(bs);
        kfree(raw);
        return false;
    }
#endif

    // Copier les donnees du boot sector
    memcpy(bs, raw->data, sizeof(fat32_boot_sector_t));

    // Test de lecture securisee
    uint16_t bps;
    memcpy(&bps, &bs->bytes_per_sector, sizeof(uint16_t));
    KDEBUG("bytes_per_sector (via memcpy) = %u\n", bps);

    KDEBUG("Boot sector read successful\n");
    KDEBUG("bs = %p, aligned 4 ? %s\n", bs, ((uintptr_t)bs % 4 == 0) ? "OK" : "KO");

    KDEBUG("=== STRUCTURE DIAGNOSTIC ===\n");
    KDEBUG("Structure fat32_boot_sector_t:\n");
    KDEBUG("  Base address: %p\n", bs);
    KDEBUG("  Size: %u bytes\n", sizeof(fat32_boot_sector_t));
    KDEBUG("  Alignment: %u\n", __alignof__(fat32_boot_sector_t));
    
    /* Analyse des champs du boot sector */
    KDEBUG("Boot sector field analysis:\n");
    KDEBUG("  Jump instruction: %02X %02X %02X\n", 
           bs->jump[0], bs->jump[1], bs->jump[2]);
    KDEBUG("  OEM name: '%.8s'\n", bs->oem_name);
    KDEBUG("  bytes_per_sector: %u\n", bs->bytes_per_sector);
    KDEBUG("  sectors_per_cluster: %u\n", bs->sectors_per_cluster);
    KDEBUG("  reserved_sectors: %u\n", bs->reserved_sectors);
    KDEBUG("  num_fats: %u\n", bs->num_fats);
    KDEBUG("  root_entries: %u\n", bs->root_entries);
    KDEBUG("  fat_size_16: %u\n", bs->fat_size_16);
    KDEBUG("  fat_size_32: %u\n", bs->fat_size_32);
    KDEBUG("  root_cluster: %u\n", bs->root_cluster);
    
    /* Verifier la signature de boot */
    uint16_t boot_sig = bs->boot_signature_55aa;
    KDEBUG("  boot_signature: 0x%04X\n", boot_sig);
    
    /* Validation de la signature */
    if (boot_sig != 0xAA55) {
        KERROR("FAT32: Invalid boot signature 0x%04X (expected 0xAA55)\n", boot_sig);
        kfree(bs);
        kfree(raw);
        return false;
    }
    
    /* Analyser les champs FAT32 specifiques */
    KDEBUG("FAT32 specific fields:\n");
    KDEBUG("  fs_type field: '%.8s'\n", bs->fs_type);
    
    /* Verification FAT32 avec criteres relaxes */
    bool valid_fat32 = true;
    
    if (bs->bytes_per_sector != 512) {
        KERROR("FAT32: Invalid bytes_per_sector: %u (expected 512)\n", bs->bytes_per_sector);
        valid_fat32 = false;
    }
    
    if (bs->root_entries != 0) {
        KERROR("FAT32: root_entries should be 0 for FAT32, got: %u\n", bs->root_entries);
        valid_fat32 = false;
    }
    
    if (bs->fat_size_16 != 0) {
        KERROR("FAT32: fat_size_16 should be 0 for FAT32, got: %u\n", bs->fat_size_16);
        valid_fat32 = false;
    }
    
    if (bs->fat_size_32 == 0) {
        KERROR("FAT32: fat_size_32 cannot be 0 for FAT32\n");
        valid_fat32 = false;
    }
    
    /* Verification de la chaine FS type (non critique) */
    if (strncmp(bs->fs_type, "FAT32   ", 8) != 0) {
        KWARN("FAT32: fs_type string is '%.8s' (expected 'FAT32   ')\n", bs->fs_type);
        KWARN("FAT32: Continuing anyway (some mkfs don't set this correctly)\n");
    }
    
    if (!valid_fat32) {
        KERROR("FAT32: Filesystem validation failed\n");
        kfree(bs);
        kfree(raw);
        return false;
    }

    KINFO("FAT32: Basic validation passed\n");
    
    /* Calculer les offsets du filesystem */
    fat32_fs.fat_start_sector = bs->reserved_sectors;
    fat32_fs.data_start_sector = bs->reserved_sectors + (bs->num_fats * bs->fat_size_32);
    fat32_fs.root_dir_cluster = bs->root_cluster;
    fat32_fs.sectors_per_cluster = bs->sectors_per_cluster;
    fat32_fs.bytes_per_cluster = bs->sectors_per_cluster * bs->bytes_per_sector;

    KINFO("FAT32 layout:\n");
    KINFO("  FAT start: sector %u\n", fat32_fs.fat_start_sector);
    KINFO("  Data start: sector %u\n", fat32_fs.data_start_sector);
    KINFO("  Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("  Cluster size: %u bytes\n", fat32_fs.bytes_per_cluster);
    
    /* Charger la table FAT */
    fat_sectors = bs->fat_size_32;
    KDEBUG("Allocating %u sectors for FAT table...\n", fat_sectors);
    
    fat32_fs.fat_table = kmalloc(fat_sectors * 512);
    if (!fat32_fs.fat_table) {
        KERROR("FAT32: Failed to allocate FAT table (%u bytes)\n", fat_sectors * 512);
        kfree(bs);
        kfree(raw);
        return false;
    }

    KDEBUG("Reading FAT table from sector %u...\n", fat32_fs.fat_start_sector);
    
#ifdef USE_RAMFS
    if (ramfs_read_sectors(fat32_fs.fat_start_sector, fat_sectors, fat32_fs.fat_table) < 0) {
        KERROR("FAT32: Failed to read FAT table from RAMFS\n");
        kfree(fat32_fs.fat_table);
        kfree(bs);
        kfree(raw);
        return false;
    }
#else
    if (ata_read_sectors(fat32_fs.fat_start_sector, fat_sectors, fat32_fs.fat_table) < 0) {
        KERROR("FAT32: Failed to read FAT table from ATA\n");
        kfree(fat32_fs.fat_table);
        kfree(bs);
        kfree(raw);
        return false;
    }
#endif
    
    fat32_fs.mounted = true;
    
    KINFO("FAT32: Mount successful! OK\n");

    kfree(raw);
    kfree(bs);
    
    return true;
}

/* Fonction utilitaire pour tester l'ATA avant FAT32 */
bool test_ata_before_fat32(void)
{
    KINFO("Testing ATA device before FAT32 mount...\n");
    
    if (!ata_is_initialized()) {
        KERROR("ATA device not initialized\n");
        return false;
    }
    
    /* Test de lecture du premier secteur */
    static uint8_t test_buffer[516] __attribute__((aligned(8)));
    KINFO("\n\n********************************\n");
    
    KDEBUG("Reading sector 0 for test...\n");
    if (ata_read_sectors_debug(0, 1, test_buffer) < 0) {
        KERROR("Failed to read test sector\n");
        return false;
    }

    KINFO("\n\n********************************\n");
    
    /* Verifier que ce n'est pas tout zero */
    bool all_zero = true;
    for (int i = 0; i < 512; i++) {
        if (test_buffer[i] != 0) {
            all_zero = false;
            break;
        }
    }
    
    if (all_zero) {
        KERROR("Sector 0 is all zeros - disk may be empty\n");
        return false;
    }
    
    KINFO("ATA test passed - sector 0 contains data\n");
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

uint32_t get_next_cluster(uint32_t cluster)
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
        cluster = get_next_cluster(cluster);
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
            if (entry->name[0] == 0xE5) continue;
            
            /* LFN entry */
            if (entry->attr == FAT_ATTR_LFN) continue;
            
            /* Convert name and compare */
            fat32_83_to_name(entry->name, entry_name);
            
            if (strcmp(entry_name, filename) == 0) {
                result = kmalloc(sizeof(fat32_dir_entry_t));
                if (result) {
                    memcpy(result, entry, sizeof(fat32_dir_entry_t));
                }
                kfree(cluster_buf);
                return result;
            }
        }
        
        kfree(cluster_buf);
        cluster = get_next_cluster(cluster);
    }
    
    return NULL;
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



void debug_src_pointer_issue(const fat32_raw_sector_t* raw)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("=== DEBUGGING SRC POINTER ===\n");
    
    /* Test 1: Verifier raw */
    kprintf("raw = 0x%08X\n", (uint32_t)raw);
    
    /* Test 2: Verifier raw->data SANS arithmetique */
    const uint8_t* src = raw->data;
    kprintf("src = 0x%08X\n", (uint32_t)src);
    
    /* Test 3: Verifier que src est valide AVANT arithmetique */
    kprintf("Testing src validity...\n");
    
    /* Test d'acces direct a src[0] */
    kprintf("About to read src[0]...\n");
    uint8_t test_byte = src[0];  /* Peut crasher ICI */
    kprintf("src[0] = 0x%02X\n", test_byte);
    
    /* Test d'acces a src[11] DIRECTEMENT */
    kprintf("About to read src[11]...\n");
    uint8_t test_byte11 = src[11];  /* Peut crasher ICI */
    kprintf("src[11] = 0x%02X\n", test_byte11);
    
    /* Test arithmetique simple */
    kprintf("About to test pointer arithmetic...\n");
    const uint8_t* test_ptr = src + 1;  /* Peut crasher ICI */
    kprintf("src + 1 = 0x%08X\n", (uint32_t)test_ptr);
    
    const uint8_t* test_ptr11 = src + 11;  /* Peut crasher ICI */
    kprintf("src + 11 = 0x%08X\n", (uint32_t)test_ptr11);
    
    kprintf("=== END DEBUG ===\n");
}

/* === SOLUTION: VALIDATION COMPLeTE DE src === */

bool validate_src_pointer(const fat32_raw_sector_t* raw)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("=== VALIDATING SRC POINTER ===\n");
    
    /* Verification 1: raw n'est pas NULL */
    if (!raw) {
        kprintf("KO raw is NULL\n");
        return false;
    }
    kprintf("OK raw is valid: 0x%08X\n", (uint32_t)raw);
    
    /* Verification 2: Adresse raw dans la plage valide */
    uint32_t raw_addr = (uint32_t)raw;
    if (raw_addr < 0x60000000 || raw_addr > 0x80000000) {
        kprintf("KO raw outside valid memory: 0x%08X\n", raw_addr);
        return false;
    }
    kprintf("OK raw in valid memory range\n");
    
    /* Verification 3: raw->data accessible */
    const uint8_t* src;
    
    /* Acces TReS prudent a raw->data */
    __asm__ volatile (
        "ldr %0, [%1]\n"    /* Charger raw->data */
        : "=r"(src)
        : "r"(raw)
        : "memory"
    );
    
    kprintf("src (raw->data) = 0x%08X\n", (uint32_t)src);
    
    /* Verification 4: src dans la plage valide */
    uint32_t src_addr = (uint32_t)src;
    if (src_addr < 0x60000000 || src_addr > 0x80000000) {
        kprintf("KO src outside valid memory: 0x%08X\n", src_addr);
        return false;
    }
    kprintf("OK src in valid memory range\n");
    
    /* Verification 5: Test d'acces direct sans arithmetique */
    kprintf("Testing direct access without arithmetic...\n");
    
    uint8_t first_byte = src[0];
    kprintf("src[0] = 0x%02X\n", first_byte);
    
    /* Verification 6: Test de tous les offsets critiques un par un */
    kprintf("Testing critical offsets...\n");
    
    for (int offset = 0; offset <= 0x20; offset++) {
        uint8_t test_byte = src[offset];  /* Peut crasher */
        if (offset == 0x0B) {
            kprintf("OK src[0x%02X] = 0x%02X (bytes_per_sector LSB)\n", offset, test_byte);
        }
    }

    run_pointer_arithmetic_test(raw);
    
    kprintf("OK All offset tests passed\n");
    return true;
}

/* === VERSION ULTRA-SeCURISeE DU PARSING === */
#if(0)
void fat32_parse_boot_sector_ultra_safe(fat32_boot_sector_t* dst, const fat32_raw_sector_t* raw)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("=== ULTRA-SAFE FAT32 PARSING ===\n");
    
    /* Validation complete avant toute operation */
    if (!validate_src_pointer(raw)) {
        kprintf("KO src pointer validation failed\n");
        return;
    }
    
    const uint8_t* src = raw->data;
    kprintf("OK src validated: 0x%08X\n", (uint32_t)src);
    
    /* Parse avec acces par index uniquement (pas d'arithmetique) */
    kprintf("Parsing header...\n");
    dst->jump[0] = src[0];
    dst->jump[1] = src[1];
    dst->jump[2] = src[2];
    kprintf("Jump: %02X %02X %02X\n", dst->jump[0], dst->jump[1], dst->jump[2]);
    
    /* OEM name */
    for (int i = 0; i < 8; i++) {
        dst->oem_name[i] = src[3 + i];
    }
    dst->oem_name[8] = '\0';
    kprintf("OEM: '%s'\n", dst->oem_name);
    
    /* bytes_per_sector avec acces par index */
    kprintf("Reading bytes_per_sector...\n");
    uint8_t bps_lsb = src[0x0B];  /* Premier test critique */
    kprintf("BPS LSB = 0x%02X\n", bps_lsb);
    
    uint8_t bps_msb = src[0x0C];  /* Deuxieme test critique */
    kprintf("BPS MSB = 0x%02X\n", bps_msb);
    
    kprintf("ICI\n");
    uint16_t var1 = (uint16_t)bps_lsb | ((uint16_t)bps_msb << 8);
    kprintf("(uint16_t)bps_lsb | ((uint16_t)bps_msb << 8) = %u\n", var1) ;
    kprintf("Adresse de dst->bytes_per_sector %p \n", &(dst->bytes_per_sector));
    kprintf("Affectation directe de 512 a dst->bytes_per_sector\n");
    dst->bytes_per_sector = 512 ;
    kprintf("Apres affectation directe dst->bytes_per_sector = %d\n", dst->bytes_per_sector);
    kprintf("tout va bien ici\n") ;

    kprintf("bytes_per_sector = %u\n", dst->bytes_per_sector);

    
    /* Continue with other fields using index access only */
    dst->sectors_per_cluster = src[0x0D];
    kprintf("sectors_per_cluster = %u\n", dst->sectors_per_cluster);
    
    /* reserved_sectors */
    dst->reserved_sectors = (uint16_t)src[0x0E] | ((uint16_t)src[0x0F] << 8);
    kprintf("reserved_sectors = %u\n", dst->reserved_sectors);
    
    /* Continue with all other fields... */
    dst->num_fats = src[0x10];
    dst->root_entries = (uint16_t)src[0x11] | ((uint16_t)src[0x12] << 8);
    dst->total_sectors_16 = (uint16_t)src[0x13] | ((uint16_t)src[0x14] << 8);
    dst->media_type = src[0x15];
    dst->fat_size_16 = (uint16_t)src[0x16] | ((uint16_t)src[0x17] << 8);
    dst->sectors_per_track = (uint16_t)src[0x18] | ((uint16_t)src[0x19] << 8);
    dst->num_heads = (uint16_t)src[0x1A] | ((uint16_t)src[0x1B] << 8);
    
    /* hidden_sectors (32-bit) */
    dst->hidden_sectors = (uint32_t)src[0x1C] | ((uint32_t)src[0x1D] << 8) |
                         ((uint32_t)src[0x1E] << 16) | ((uint32_t)src[0x1F] << 24);
    
    /* total_sectors_32 */
    dst->total_sectors_32 = (uint32_t)src[0x20] | ((uint32_t)src[0x21] << 8) |
                           ((uint32_t)src[0x22] << 16) | ((uint32_t)src[0x23] << 24);
    
    /* FAT32 extended fields */
    dst->fat_size_32 = (uint32_t)src[0x24] | ((uint32_t)src[0x25] << 8) |
                      ((uint32_t)src[0x26] << 16) | ((uint32_t)src[0x27] << 24);
    kprintf("fat_size_32 = %u\n", dst->fat_size_32);
    
    dst->ext_flags = (uint16_t)src[0x28] | ((uint16_t)src[0x29] << 8);
    dst->fs_version = (uint16_t)src[0x2A] | ((uint16_t)src[0x2B] << 8);
    
    dst->root_cluster = (uint32_t)src[0x2C] | ((uint32_t)src[0x2D] << 8) |
                       ((uint32_t)src[0x2E] << 16) | ((uint32_t)src[0x2F] << 24);
    kprintf("root_cluster = %u\n", dst->root_cluster);
    
    dst->fs_info = (uint16_t)src[0x30] | ((uint16_t)src[0x31] << 8);
    dst->backup_boot = (uint16_t)src[0x32] | ((uint16_t)src[0x33] << 8);
    
    /* Reserved area */
    for (int i = 0; i < 12; i++) {
        dst->reserved[i] = src[0x34 + i];
    }
    
    /* Extended fields */
    dst->drive_number = src[0x40];
    dst->reserved1 = src[0x41];
    dst->boot_signature = src[0x42];
    
    dst->volume_id = (uint32_t)src[0x43] | ((uint32_t)src[0x44] << 8) |
                    ((uint32_t)src[0x45] << 16) | ((uint32_t)src[0x46] << 24);
    
    /* Volume label and fs type */
    for (int i = 0; i < 11; i++) {
        dst->volume_label[i] = src[0x47 + i];
    }
    dst->volume_label[11] = '\0';
    
    for (int i = 0; i < 8; i++) {
        dst->fs_type[i] = src[0x52 + i];
    }
    dst->fs_type[8] = '\0';
    
    /* Boot signature */
    dst->boot_signature_55aa = (uint16_t)src[0x1FE] | ((uint16_t)src[0x1FF] << 8);
    
    kprintf("OK Ultra-safe parsing completed successfully\n");
    kprintf("Volume: '%.11s', FS: '%.8s'\n", dst->volume_label, dst->fs_type);
}
#endif
/* === TEST DE DIAGNOSTIC === */

void run_pointer_arithmetic_test(const fat32_raw_sector_t* raw)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("\nDEBUG === POINTER ARITHMETIC DIAGNOSTIC === DEBUG\n");
    
    /* Test progressif pour identifier ou ca crash */
    debug_src_pointer_issue(raw);
    
    kprintf("DEBUG === END DIAGNOSTIC === DEBUG\n\n");
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
 * Monte le systeme de fichiers FAT32 depuis RAMFS
 */
int mount_fat32_filesystem(void)
{
    KINFO("[FAT32] Montage du systeme de fichiers...\n");
    
    /* Appeler fat32_mount() existant */
    if (!fat32_mount()) {
        KERROR("[FAT32] echec du montage\n");
        return -1;
    }

    //KDEBUG("=== TESTING FAT TABLE ===\n");

    /* Vérifier les premières entrées de la FAT */
    //for (uint32_t i = 0; i < 10; i++) {
    //    uint32_t fat_entry = fat32_fs.fat_table[i] & 0x0FFFFFFF;
    //    KDEBUG("FAT[%u] = 0x%08X\n", i, fat_entry);
    //}

    /* Test spécifique du root cluster */
    //uint32_t root_next = get_next_cluster(fat32_fs.root_dir_cluster);
    //KDEBUG("Root cluster %u -> next cluster %u\n", fat32_fs.root_dir_cluster, root_next);

    //KDEBUG("=== END FAT TABLE TEST ===\n");

        /* À la fin de fat32_mount, avant return true */
    //KDEBUG("=== TESTING CLUSTER CONVERSION ===\n");

    /* Tester la conversion cluster→secteur */
/*     for (uint32_t test_cluster = 2; test_cluster <= 10; test_cluster++) {
        uint32_t test_sector = cluster_to_sector(test_cluster);
        KDEBUG("Cluster %u -> sector %u\n", test_cluster, test_sector);
        
        // Test de lecture directe
        char test_buf[512];
        if (ramfs_read_sectors(test_sector, 1, test_buf)) {
            KDEBUG("  Sector %u readable: %02X %02X %02X %02X\n",
                test_sector, test_buf[0], test_buf[1], test_buf[2], test_buf[3]);
        } else {
            KDEBUG("  Sector %u NOT readable\n", test_sector);
        }
    }

    KDEBUG("=== END CLUSTER TEST ===\n"); */
    
    KINFO("[FAT32] Systeme de fichiers monte avec succes\n");
    KINFO("[FAT32]   Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("[FAT32]   Data start: secteur %u\n", fat32_fs.data_start_sector);
    KINFO("[FAT32]   Bytes per cluster: %u\n", fat32_fs.bytes_per_cluster);
    
    return 0;
}

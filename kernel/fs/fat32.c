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

extern int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer);
extern int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer);
extern int blk_read_sector(uint64_t lba, void* buffer);
extern int blk_write_sector(uint64_t lba, void* buffer);

bool blk_is_initialized(void);


#ifdef USE_RAMFS
    #define storage_read_sectors(lba, count, buffer) blk_read_sectors(lba, count, buffer)
    #define storage_write_sectors(lba, count, buffer) blk_write_sectors(lba, count, buffer)
    #define storage_is_initialized() blk_is_initialized()
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

extern bool is_fat_dirty(void);
extern bool is_dirty_inodes(void);
extern void sync_fat_to_disk(void);
extern void sync_dirty_inodes(void);

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

extern int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer);
extern int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer);

bool fat32_mount(){

    KDEBUG("Mounting FAT32 from VIRTIO MMIO BLK DEVICE...\n");
    
    /* Verifier que RAMFS est initialise */
/*     if (!ramfs_is_initialized()) {
        KERROR("FAT32: RAMFS not initialized\n");
        return false;
    } */
    extern uint32_t ata_sector_size;
    if( ata_sector_size == 0) return false;

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
    if (blk_read_sectors(0, 1, raw->data) < 0) {
        KERROR("Failed to read boot sector from RAMFS\n");
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
    
    /* CORRECTION: Calculer correctement les offsets */
    fat32_fs.fat_start_sector = fat32_fs.boot_sector.reserved_sectors;
    fat32_fs.data_start_sector = fat32_fs.boot_sector.reserved_sectors + (fat32_fs.boot_sector.num_fats * fat32_fs.boot_sector.fat_size_32);
    fat32_fs.root_dir_cluster = fat32_fs.boot_sector.root_cluster;
    fat32_fs.sectors_per_cluster = fat32_fs.boot_sector.sectors_per_cluster;
    fat32_fs.bytes_per_cluster = fat32_fs.boot_sector.sectors_per_cluster * fat32_fs.boot_sector.bytes_per_sector;
    
    KINFO("FAT32 layout calculated:\n");
    KINFO("  FAT start: sector %u\n", fat32_fs.fat_start_sector);
    KINFO("  Data start: sector %u\n", fat32_fs.data_start_sector);
    KINFO("  Root cluster: %u\n", fat32_fs.root_dir_cluster);
    KINFO("  Cluster size: %u bytes\n", fat32_fs.bytes_per_cluster);
    
    /* Charger la table FAT */
    uint32_t fat_size_bytes = fat32_fs.boot_sector.fat_size_32 * 512;
    fat32_fs.fat_table = kmalloc(fat_size_bytes);
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
    extern void read_sector0_and_print(void);
    read_sector0_and_print();

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

uint32_t fat32_get_next_cluster(uint32_t cluster)
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
        cluster = fat32_get_next_cluster(cluster);
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
    //uint32_t root_next = fat32_get_next_cluster(fat32_fs.root_dir_cluster);
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

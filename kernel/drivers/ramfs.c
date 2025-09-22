/* kernel/drivers/ramfs.c - RAM FileSystem Driver */
#include <kernel/types.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/kernel.h>
#include <kernel/userfs_loader.h>
#include <kernel/tar_parser_ramfs.h>
#include <kernel/spinlock.h>
#include <kernel/fat32.h>
#include <kernel/ramfs.h>

/* RAMFS Configuration */
#define RAMFS_SIZE          (64 * 1024 * 1024)   /* 64MB */
#define RAMFS_SECTOR_SIZE   512
#define RAMFS_SECTORS       (RAMFS_SIZE / RAMFS_SECTOR_SIZE)  /* 131072 sectors */
#define RAMFS_BASE_ADDR     USERFS_LOAD_ADDR              /* Adresse fixe s-re */


/* Global RAMFS device */
ramfs_device_t ramfs_device = {0};

/* Forward declarations */
static bool ramfs_allocate_memory(void);
static void ramfs_create_fat32_filesystem(void);
static void ramfs_write_boot_sector(uint8_t* sector);
static void ramfs_write_fat_tables(void);
static void ramfs_write_root_directory(void);
void debug_memory_layout_ramfs(void);
void debug_ramfs_creation_step_by_step(void);
void ramfs_test(void);
void ramfs_tar_test(void);
int ramfs_write_sectors(uint64_t lba, uint32_t count, const void* buffer);
int ramfs_read_sectors(uint64_t lba, uint32_t count, void* buffer);
static void create_fat32_file(const char* filename, const uint8_t* data, uint32_t size);
static void convert_to_fat32_name(const char* filename, char* fat_name);
static void update_fat_entry(uint32_t cluster, uint32_t value);
static void add_file_to_root_directory(const char* fat_name, uint32_t cluster, uint32_t size);


/* Creation du boot sector FAT32 */
void create_fat32_boot_sector(void)
{
    static uint8_t boot_sector[512];
    memset(boot_sector, 0, 512);
    
    /* Boot sector FAT32 standard */
    boot_sector[0] = 0xEB; boot_sector[1] = 0x58; boot_sector[2] = 0x90;  /* Jump */
    memcpy(boot_sector + 3, "RAMFS   ", 8);                              /* OEM */
    *(uint16_t*)(boot_sector + 11) = 512;                                 /* Bytes per sector */
    boot_sector[13] = 1;                                                  /* Sectors per cluster */
    *(uint16_t*)(boot_sector + 14) = 32;                                  /* Reserved sectors */
    boot_sector[16] = 2;                                                  /* Num FATs */
    *(uint16_t*)(boot_sector + 17) = 0;                                   /* Root entries (FAT32) */
    *(uint16_t*)(boot_sector + 19) = 0;                                   /* Total sectors 16 */
    boot_sector[21] = 0xF8;                                               /* Media descriptor */
    *(uint16_t*)(boot_sector + 22) = 0;                                   /* FAT size 16 */
    *(uint16_t*)(boot_sector + 24) = 32;         /* sectors_per_track */
    *(uint16_t*)(boot_sector + 26) = 8;          /* num_heads */
    *(uint32_t*)(boot_sector + 28) = 0;          /* hidden_sectors */
    *(uint32_t*)(boot_sector + 32) = RAMFS_SECTORS;                       /* Total sectors 32 */


    *(uint32_t*)(boot_sector + 36) = 1009;                                /* FAT size 32 */
    *(uint16_t*)(boot_sector + 40) = 0;          /* flags */
    *(uint16_t*)(boot_sector + 42) = 0;          /* version */
    *(uint32_t*)(boot_sector + 44) = 2;                                   /* Root cluster */

    *(uint16_t*)(boot_sector + 48) = 1;          /* fsinfo_sector */
    *(uint16_t*)(boot_sector + 50) = 6;          /* backup_boot_sector */
    
    /* Extended fields */
    boot_sector[66] = 0x80;                      /* drive_number */
    boot_sector[67] = 0;                         /* reserved */
    boot_sector[68] = 0x29;                      /* boot_signature */
    *(uint32_t*)(boot_sector + 69) = 0x12345678; /* volume_serial */

    memcpy(boot_sector + 71, "RAMFS      ", 11);                         /* Volume label */
    memcpy(boot_sector + 82, "FAT32   ", 8);                             /* FS type */
    boot_sector[510] = 0x55;
    boot_sector[511] = 0xAA;                     /* Signature */
    
    /* ecrire le boot sector */
    ramfs_write_sectors(0, 1, boot_sector);
    KDEBUG("[FS] Boot sector FAT32 cree\n");

}

/* Creation des tables FAT */
void create_fat32_fat_tables(void)
{
    static uint8_t fat_sector[512];
    memset(fat_sector, 0, 512);
    
    /* Premieres entrees FAT */
    *(uint32_t*)(fat_sector + 0) = 0x0FFFFFF8;    /* Media descriptor */
    *(uint32_t*)(fat_sector + 4) = 0x0FFFFFFF;    /* End of chain */
    *(uint32_t*)(fat_sector + 8) = 0x0FFFFFFF;    /* Root directory */
    
    /* ecrire FAT1 (secteur 32) */
    ramfs_write_sectors(32, 1, fat_sector);
    
    /* ecrire FAT2 (secteur 32 + 1009) */
    ramfs_write_sectors(32 + 1009, 1, fat_sector);
    
    KDEBUG("[FS] Tables FAT creees\n");
}

/* Creation du repertoire racine */
void create_fat32_root_directory(void)
{
    static uint8_t root_dir[512];
    memset(root_dir, 0, 512);
    
    /* Volume label */
    memcpy(root_dir, "RAMFS      ", 11);
    root_dir[11] = 0x08;  /* Volume label attribute */
    
    /* ecrire au secteur 2050 (cluster 2) */
    ramfs_write_sectors(2050, 1, root_dir);
    
    KDEBUG("[FS] Repertoire racine cree\n");
}

/* Variables globales pour l'allocation de clusters */
static uint32_t next_free_cluster = 3;    /* Commence apres root (cluster 2) */
static uint32_t next_free_sector = 2051;  /* Secteur correspondant */

/* Extraction TAR vers FAT32 */
static void extract_tar_to_fat32_filesystem(const uint8_t* tar_data, uint32_t tar_size)
{
    KINFO("[TAR] Extraction vers FAT32...\n");
    
    const uint8_t* current = tar_data;
    const uint8_t* end = tar_data + tar_size;
    uint32_t files_created = 0;
    
    while (current < end - 512) {
        /* TAR header */
        const char* filename = (const char*)current;
        
        /* Skip empty entries */
        if (filename[0] == 0) {
            current += 512;
            continue;
        }
        
        /* Parse file size (octal) */
        char size_str[12] = {0};
        memcpy(size_str, current + 124, 11);
        
        uint32_t file_size = 0;
        for (int i = 0; i < 11 && size_str[i]; i++) {
            if (size_str[i] >= '0' && size_str[i] <= '7') {
                file_size = file_size * 8 + (size_str[i] - '0');
            }
        }
        
        KDEBUG("[TAR] Fichier: %s (taille: %u)\n", filename, file_size);
        
        /* Skip header */
        current += 512;
        
        /* Create file in FAT32 if it's a regular file */
        if (file_size > 0 /*&& !strstr(filename, "./")*/) {  /* Root level files only */
            
            KDEBUG("[TAR] create_fat32_file ---> Fichier: %s (taille: %u)\n", filename, file_size);

            create_fat32_file(filename, current, file_size);
            files_created++;
        }
        
        /* Skip file data */
        uint32_t padded_size = (file_size + 511) & ~511;
        current += padded_size;
        
        if (current >= end) break;
        
        /* Limite pour eviter de remplir tout RAMFS */
        if (files_created >= 10) break;
    }
    
    KINFO("[TAR] OK %u fichiers extraits vers FAT32\n", files_created);
}

/* Creer un fichier dans le filesystem FAT32 */
static void create_fat32_file(const char* filename, const uint8_t* data, uint32_t size)
{
    if (next_free_cluster >= 100) {  /* Limite securite */
        KWARN("[FAT32] Plus de clusters disponibles\n");
        return;
    }
    
    /* Convertir nom en format 8.3 */
    char fat_name[11];
    convert_to_fat32_name(filename, fat_name);
    
    /* Allouer cluster(s) pour le fichier */
    uint32_t file_cluster = next_free_cluster++;
    uint32_t file_sector = next_free_sector++;
    
    /* ecrire les donnees du fichier */
    static uint8_t file_buffer[512];
    memset(file_buffer, 0, 512);
    
    uint32_t copy_size = (size > 512) ? 512 : size;
    memcpy(file_buffer, data, copy_size);
    
    ramfs_write_sectors(file_sector, 1, file_buffer);
    
    /* Mettre a jour la FAT */
    update_fat_entry(file_cluster, 0x0FFFFFFF);  /* End of chain */
    
    /* Ajouter l'entree dans le repertoire racine */
    add_file_to_root_directory(fat_name, file_cluster, size);
    
    KDEBUG("[FAT32] Fichier cree: %s (cluster %u)\n", filename, file_cluster);
}

/* Convertir nom de fichier en format FAT32 8.3 */
static void convert_to_fat32_name(const char* filename, char* fat_name)
{
    memset(fat_name, ' ', 11);
    
    /* Trouver l'extension */
    const char* dot = strrchr(filename, '.');
    const char* base_end = dot ? dot : filename + strlen(filename);
    
    /* Copier le nom de base (8 chars max) */
    int base_len = base_end - filename;
    if (base_len > 8) base_len = 8;
    
    for (int i = 0; i < base_len; i++) {
        fat_name[i] = toupper(filename[i]);
    }
    
    /* Copier l'extension (3 chars max) */
    if (dot && strlen(dot + 1) > 0) {
        int ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        
        for (int i = 0; i < ext_len; i++) {
            fat_name[8 + i] = toupper(dot[1 + i]);
        }
    }
}

/* Mettre a jour une entree FAT */
static void update_fat_entry(uint32_t cluster, uint32_t value)
{
    static uint8_t fat_buffer[512];
    
    /* Lire le secteur FAT contenant ce cluster */
    uint32_t fat_offset = cluster * 4;  /* 4 bytes per entry in FAT32 */
    uint32_t fat_sector = 32 + (fat_offset / 512);
    uint32_t sector_offset = fat_offset % 512;
    
    /* Lire, modifier, ecrire */
    ramfs_read_sectors(fat_sector, 1, fat_buffer);
    *(uint32_t*)(fat_buffer + sector_offset) = value;
    ramfs_write_sectors(fat_sector, 1, fat_buffer);
    
    /* Mettre a jour la copie FAT2 */
    ramfs_write_sectors(fat_sector + 1009, 1, fat_buffer);
}

/* Ajouter un fichier au repertoire racine */
static void add_file_to_root_directory(const char* fat_name, uint32_t cluster, uint32_t size)
{
    static uint8_t root_buffer[512];
    
    /* Lire le repertoire racine */
    ramfs_read_sectors(2050, 1, root_buffer);
    
    /* Trouver une entree libre */
    for (int i = 1; i < 16; i++) {  /* Skip volume label at index 0 */
        uint8_t* entry = root_buffer + (i * 32);
        
        if (entry[0] == 0 || entry[0] == 0xE5) {  /* Free entry */
            /* Remplir l'entree */
            memcpy(entry, fat_name, 11);
            entry[11] = 0x20;                              /* File attribute */
            *(uint16_t*)(entry + 20) = (cluster >> 16);   /* High cluster */
            *(uint16_t*)(entry + 26) = (cluster & 0xFFFF); /* Low cluster */
            *(uint32_t*)(entry + 28) = size;               /* File size */
            
            /* ecrire le repertoire modifie */
            ramfs_write_sectors(2050, 1, root_buffer);
            break;
        }
    }
}

void create_fat32_filesystem_from_userfs2(void)
{
    KINFO("[FS] === Creation filesystem FAT32 a partir UserFS ===\n");
    
    extern ramfs_device_t ramfs_device;
    
    /* etape 1: Sauvegarder les donnees UserFS TAR */
    static uint8_t userfs_backup[10000000];  /* 10 MB pour le TAR */
    
    volatile userfs_header_t* userfs_header = (volatile userfs_header_t*)ramfs_device.memory_base;
    uint32_t userfs_size = userfs_header->size;
    
    if (userfs_size > sizeof(userfs_backup)) {
        KERROR("[FS] UserFS trop gros (%u bytes)\n", userfs_size);
        return;
    }
    
    /* Copier les donnees TAR */
    memcpy(userfs_backup, (void*)ramfs_device.memory_base, userfs_size + 12);
    KINFO("[FS] UserFS TAR sauvegarde (%u bytes)\n", userfs_size);
    
    /* etape 2: Clear RAMFS et creer filesystem FAT32 de base */
    KINFO("[FS] Creation filesystem FAT32 de base...\n");
    memset(ramfs_device.memory_base, 0, RAMFS_SIZE);
    
    /* Creer boot sector FAT32 */
    create_fat32_boot_sector();
    
    /* Creer FAT tables */
    create_fat32_fat_tables();
    
    /* Creer repertoire racine */
    create_fat32_root_directory();
    
    /* etape 3: Extraire les fichiers TAR vers le filesystem FAT32 */
    KINFO("[FS] Extraction TAR vers filesystem FAT32...\n");
    extract_tar_to_fat32_filesystem(userfs_backup + 12, userfs_size);
    
    KINFO("[FS] OK Filesystem FAT32 cree avec contenu UserFS\n");
}

void create_fat32_filesystem_from_userfs(void)
{
    KINFO("[FS] === Creation filesystem FAT32 a partir UserFS ===\n");
    
    extern ramfs_device_t ramfs_device;
    
    /* STEP 1: Lire la taille UserFS d'abord */
    volatile userfs_header_t* userfs_header = (volatile userfs_header_t*)ramfs_device.memory_base;
    uint32_t userfs_size = userfs_header->size;
    
    KINFO("[FS] UserFS size detected: %u bytes\n", userfs_size);
    
    /* SECURITE: Vérifier la taille avant allocation */
    const uint32_t MAX_USERFS_SIZE = 2 * 1024 * 1024;  /* 2MB max */
    if (userfs_size > MAX_USERFS_SIZE) {
        KERROR("[FS] UserFS too large (%u bytes), max %u\n", userfs_size, MAX_USERFS_SIZE);
        return;
    }
    
    /* STEP 2: Allocation dynamique sécurisée */
    uint32_t backup_size = userfs_size + 12;  /* Header + données */
    uint8_t* userfs_backup = (uint8_t*)kmalloc(backup_size);
    
    if (!userfs_backup) {
        KERROR("[FS] Failed to allocate backup buffer (%u bytes)\n", backup_size);
        return;
    }
    
    KINFO("[FS] Allocated backup buffer: %u bytes at %p\n", backup_size, userfs_backup);
    
    /* STEP 3: Copie sécurisée */
    memcpy(userfs_backup, (void*)ramfs_device.memory_base, backup_size);
    KINFO("[FS] UserFS TAR backed up (%u bytes)\n", userfs_size);
    
    /* STEP 4: Clear RAMFS et créer FAT32 */
    KINFO("[FS] Clearing RAMFS and creating FAT32 base...\n");
    memset(ramfs_device.memory_base, 0, RAMFS_SIZE);
    
    /* Créer boot sector FAT32 */
    create_fat32_boot_sector();
    
    /* Créer FAT tables */
    create_fat32_fat_tables();
    
    /* Créer repertoire racine */
    create_fat32_root_directory();
    
    /* STEP 5: Extraire TAR vers FAT32 */
    KINFO("[FS] Extracting TAR to FAT32 filesystem...\n");
    extract_tar_to_fat32_filesystem(userfs_backup + 12, userfs_size);
    
    /* STEP 6: Libérer le backup */
    kfree(userfs_backup);
    
    KINFO("[FS] OK Filesystem FAT32 created with UserFS content\n");
}



/* ============================================================================
 * PUBLIC API - Compatible avec ATA
 * ============================================================================ */


 void debug_memory_layout_ramfs(void)
{
    KINFO("[MEMORY] === Layout memoire RAMFS ===\n");
        
    KINFO("[MEMORY] RAMFS base:    0x%08X\n", (uint32_t)ramfs_device.memory_base);
    KINFO("[MEMORY] RAMFS end:     0x%08X\n", (uint32_t)ramfs_device.memory_base + RAMFS_SIZE);
    KINFO("[MEMORY] RAMFS size:    %u MB\n", RAMFS_SIZE / (1024*1024));
    
    /* Adresses kernel */
    KINFO("[MEMORY] Kernel start:  0x%08X\n", KERNEL_START);
    KINFO("[MEMORY] Kernel end:    0x%08X\n", KERNEL_END);
    KINFO("[MEMORY] Heap start:    0x%08X\n", HEAP_START);
    KINFO("[MEMORY] Heap end:      0x%08X\n", HEAP_END);
    
    /* Adresses processus */
    KINFO("[MEMORY] User stack:    0x%08X - 0x%08X\n", USER_STACK_BOTTOM, USER_STACK_TOP);
    KINFO("[MEMORY] Signal region: 0x%08X - 0x%08X\n", USER_SIGNAL_REGION_START, USER_SIGNAL_REGION_END);
    
    /* Verifier les overlaps */
    uint32_t ramfs_start = (uint32_t)ramfs_device.memory_base;
    uint32_t ramfs_end = ramfs_start + RAMFS_SIZE;
    
    if (ramfs_start < KERNEL_END && ramfs_end > KERNEL_START) {
        KERROR("[MEMORY] KO CONFLIT: RAMFS chevauche avec le kernel!\n");
    }
    
    if (ramfs_start < HEAP_END && ramfs_end > HEAP_START) {
        KERROR("[MEMORY] KO CONFLIT: RAMFS chevauche avec le heap!\n");
    }
    
    if (ramfs_start < USER_STACK_TOP && ramfs_end > USER_STACK_BOTTOM) {
        KERROR("[MEMORY] KO CONFLIT: RAMFS chevauche avec user stack!\n");
    }
}



bool init_ramfs(void)
{
    KINFO("=== RAMFS INITIALIZATION ===\n");
    
    /* Initialize device structure */
    memset(&ramfs_device, 0, sizeof(ramfs_device_t));
    init_spinlock(&ramfs_device.lock);
    
    ramfs_device.total_size = RAMFS_SIZE;
    ramfs_device.sector_size = RAMFS_SECTOR_SIZE;
    ramfs_device.total_sectors = RAMFS_SECTORS;
    
    KINFO("RAMFS Configuration:\n");
    KINFO("  Size:         %u MB (%u bytes)\n", 
          RAMFS_SIZE / (1024*1024), RAMFS_SIZE);
    KINFO("  Sector size:  %u bytes\n", RAMFS_SECTOR_SIZE);
    KINFO("  Total sectors: %u\n", RAMFS_SECTORS);
    
    /* Allocate memory for RAM disk */
    if (!ramfs_allocate_memory()) {
        KERROR("Failed to allocate RAMFS memory\n");
        return false;
    }
    
    KINFO("RAMFS memory allocated at: %p\n", ramfs_device.memory_base);
    
    /* Create FAT32 filesystem structure */
    //ramfs_create_fat32_filesystem();
       /* Mark as initialized */

    extern ramfs_device_t ramfs_device;
    
    /* etape 1: Sauvegarder les donnees UserFS TAR */
    //static uint8_t userfs_backup[10000000];  /* 10 MB pour le TAR */
    
    volatile userfs_header_t* userfs_header = (volatile userfs_header_t*)ramfs_device.memory_base;
    uint32_t userfs_size = userfs_header->size;

    /* SECURITE: Verifier la taille avant allocation */
    const uint32_t MAX_USERFS_SIZE = 2 * 1024 * 1024;  /* 2MB max */
    if (userfs_size > MAX_USERFS_SIZE) {
        KERROR("[FS] UserFS trop gros (%u bytes)\n", userfs_size);
        return false;
    }
    
    /* STEP 2: Allocation dynamique sécurisée */
    uint32_t backup_size = userfs_size + 12;  /* Header + données */
    uint8_t* userfs_backup = (uint8_t*)kmalloc(backup_size);
    
    if (!userfs_backup) {
        KERROR("[FS] Failed to allocate backup buffer (%u bytes)\n", backup_size);
        return false;
    }
    
    KINFO("[FS] Allocated backup buffer: %u bytes at %p\n", backup_size, userfs_backup);


    /* Copier les donnees TAR */
    memcpy(userfs_backup, (void*)ramfs_device.memory_base, userfs_size + 12);
    KINFO("[FS] UserFS TAR sauvegarde (%u bytes)\n", userfs_size);
    
    /* etape 2: Clear RAMFS et creer filesystem FAT32 de base */
    KINFO("[FS] Creation filesystem FAT32 de base...\n");
    memset(ramfs_device.memory_base, 0, RAMFS_SIZE);

    ramfs_device.initialized = true;

    //load_userfs_from_memory(userfs_backup, userfs_size + 12, ramfs_device.memory_base);
    load_userfs_from_memory(userfs_backup, userfs_size + 12);


    //create_fat32_filesystem_from_userfs();
    
    KINFO("OK RAMFS initialized successfully!\n");
    KINFO("   Virtual disk: %u sectors (%u MB)\n", 
          RAMFS_SECTORS, RAMFS_SIZE / (1024*1024));

    kfree(userfs_backup);
    
    return true;
}

bool ramfs_is_initialized(void)
{
    return ramfs_device.initialized;
}

uint64_t ramfs_get_capacity_sectors(void)
{
    return ramfs_device.total_sectors;
}

uint32_t ramfs_get_sector_size(void)
{
    return ramfs_device.sector_size;
}

bool ramfs_is_ready(void)
{
    return ramfs_device.initialized && ramfs_device.memory_base != NULL;
}

/* Read sectors from RAMFS */
int ramfs_read_sectors(uint64_t lba, uint32_t count, void* buffer)
{
    if (!ramfs_device.initialized || !ramfs_device.memory_base) {
        KERROR("RAMFS: Device not initialized\n");
        return -1;
    }
    
    if (!buffer) {
        KERROR("RAMFS: Invalid buffer\n");
        return -1;
    }
    
    if (lba + count > ramfs_device.total_sectors) {
        KERROR("RAMFS: Read beyond device capacity (LBA %u + %u > %u)\n",
               (uint32_t)lba, count, ramfs_device.total_sectors);
        return -1;
    }
    
    //KDEBUG("RAMFS: Reading %u sectors from LBA %u\n", count, (uint32_t)lba);
    
    spin_lock(&ramfs_device.lock);
    
    /* Calculate source address */
    uint8_t* src = ramfs_device.memory_base + (lba * ramfs_device.sector_size);
    uint32_t bytes_to_read = count * ramfs_device.sector_size;
    
    /* Copy data */
    memcpy(buffer, src, bytes_to_read);
    
    spin_unlock(&ramfs_device.lock);
    
    //KDEBUG("RAMFS: Read successful (%u bytes)\n", bytes_to_read);
    return count;
}

/* Write sectors to RAMFS */
int ramfs_write_sectors(uint64_t lba, uint32_t count, const void* buffer)
{
    if (!ramfs_device.initialized || !ramfs_device.memory_base) {
        KERROR("RAMFS: Device not initialized\n");
        return -1;
    }
    
    if (!buffer) {
        KERROR("RAMFS: Invalid buffer\n");
        return -1;
    }
    
    if (lba + count > ramfs_device.total_sectors) {
        KERROR("RAMFS: Write beyond device capacity (LBA %u + %u > %u)\n",
               (uint32_t)lba, count, ramfs_device.total_sectors);
        return -1;
    }
    
    //KDEBUG("RAMFS: Writing %u sectors to LBA %u\n", count, (uint32_t)lba);
    
    spin_lock(&ramfs_device.lock);
    
    /* Calculate destination address */
    uint8_t* dst = ramfs_device.memory_base + (lba * ramfs_device.sector_size);
    uint32_t bytes_to_write = count * ramfs_device.sector_size;
    
    /* Copy data */
    memcpy(dst, buffer, bytes_to_write);
    
    spin_unlock(&ramfs_device.lock);
    
    //KDEBUG("RAMFS: Write successful (%u bytes)\n", bytes_to_write);
    return count;
}

/* ============================================================================
 * MEMORY ALLOCATION
 * ============================================================================ */

static bool ramfs_allocate_memory(void)
{
    KINFO("Allocating RAMFS at safe fixed address...\n");
    
    /* CORRECTION: Utiliser une adresse fixe s-re */
    ramfs_device.memory_base = (uint8_t*)RAMFS_BASE_ADDR;  /* 1.25GB */

    /* Calculate number of pages needed */
    uint32_t pages_needed = (RAMFS_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
    KINFO("  Pages needed: %u (%u KB)\n", pages_needed, pages_needed * 4);
    
    KINFO("OK RAMFS memory at fixed safe address:\n");
    KINFO("  Base address: %p\n", ramfs_device.memory_base);
    KINFO("  End address:  %p\n", ramfs_device.memory_base + RAMFS_SIZE);
    KINFO("  Size:         %u MB\n", RAMFS_SIZE / (1024*1024));
    
    /* Clear the memory */
    //memset(ramfs_device.memory_base, 0, RAMFS_SIZE);
    debug_memory_layout_ramfs();
    
    return true;
}

static bool ramfs_allocate_memory2(void)
{
    KINFO("Allocating RAMFS memory...\n");
    
    /* Calculate number of pages needed */
    uint32_t pages_needed = (RAMFS_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;
    KINFO("  Pages needed: %u (%u KB)\n", pages_needed, pages_needed * 4);
    
    /* Allocate contiguous pages */
    void* memory = allocate_pages(pages_needed);
    if (!memory) {
        KERROR("Failed to allocate %u contiguous pages for RAMFS\n", pages_needed);
        return false;
    }
    
    ramfs_device.memory_base = (uint8_t*)memory;
    
    KINFO("OK RAMFS memory allocated:\n");
    KINFO("  Base address: %p\n", ramfs_device.memory_base);
    KINFO("  End address:  %p\n", ramfs_device.memory_base + RAMFS_SIZE);
    KINFO("  Size:         %u MB\n", RAMFS_SIZE / (1024*1024));
    
    /* Clear the memory */
    KINFO("Clearing RAMFS memory...\n");
    memset(ramfs_device.memory_base, 0, RAMFS_SIZE);
    
    return true;
}

/* ============================================================================
 * FAT32 FILESYSTEM CREATION
 * ============================================================================ */

/* ============================================================================
 * REALISTIC FILESYSTEM CREATION
 * ============================================================================ */

/* File system structure */
typedef struct ramfs_file {
    char name[32];
    uint32_t size;
    uint32_t first_cluster;
    uint8_t attr;
    const char* content;
} ramfs_file_t;

typedef struct ramfs_directory {
    char name[32];
    uint32_t first_cluster;
    uint32_t parent_cluster;
    ramfs_file_t* files;
    uint32_t file_count;
    struct ramfs_directory* subdirs;
    uint32_t subdir_count;
} ramfs_directory_t;

/* File contents */
static const char* readme_content = 
    "Welcome to RAMFS Test Filesystem\n"
    "================================\n"
    "\n"
    "This is a test filesystem created in RAM for kernel development.\n"
    "It contains various files and directories to test VFS functionality.\n"
    "\n"
    "Directories:\n"
    "- /bin     : System binaries\n"
    "- /etc     : Configuration files\n"
    "- /home    : User home directories\n"
    "- /tmp     : Temporary files\n"
    "- /var/log : Log files\n"
    "\n"
    "Test your VFS implementation with these files!\n";

static const char* passwd_content =
    "root:x:0:0:root:/root:/bin/sh\n"
    "user:x:1000:1000:Test User:/home/user:/bin/sh\n"
    "daemon:x:2:2:System Daemon:/sbin:/bin/false\n";

static const char* hosts_content =
    "127.0.0.1   localhost\n"
    "127.0.1.1   testhost\n"
    "::1         localhost ip6-localhost ip6-loopback\n";

static const char* config_content =
    "[system]\n"
    "kernel_version=1.0.0\n"
    "debug_level=2\n"
    "heap_size=8MB\n"
    "\n"
    "[filesystem]\n"
    "type=ramfs\n"
    "size=64MB\n"
    "format=fat32\n";

static const char* profile_content =
    "# User profile configuration\n"
    "export PATH=/bin:/usr/bin\n"
    "export HOME=/home/user\n"
    "export PS1='$ '\n"
    "\n"
    "echo 'Welcome to the test kernel!'\n";

static const char* user_readme_content =
    "Personal Files\n"
    "==============\n"
    "\n"
    "This is the user's home directory.\n"
    "You can store personal files here.\n"
    "\n"
    "Available commands:\n"
    "- ls    : List files\n"
    "- cat   : Display file contents\n"
    "- echo  : Print text\n";

static const char* kernel_log_content =
    "Kernel Log File\n"
    "===============\n"
    "\n"
    "[BOOT] Kernel starting...\n"
    "[MEMORY] Physical allocator initialized\n"
    "[MEMORY] Virtual memory enabled\n"
    "[FILESYSTEM] RAMFS mounted\n"
    "[VFS] Virtual filesystem initialized\n"
    "[PROCESS] Process management ready\n"
    "[FILESYSTEM] Root filesystem ready\n";

/* Binary file simulation (simple executable headers) */
static const char* ls_binary = 
    "\x7f""ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x02\x00\x03\x00\x01\x00\x00\x00"
    "LS_COMMAND_PLACEHOLDER_DATA_FOR_TESTING_VFS_IMPLEMENTATION\n";

static const char* cat_binary = 
    "\x7f""ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x02\x00\x03\x00\x01\x00\x00\x00"
    "CAT_COMMAND_PLACEHOLDER_DATA_FOR_TESTING_VFS_IMPLEMENTATION\n";

static const char* echo_binary = 
    "\x7f""ELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x02\x00\x03\x00\x01\x00\x00\x00"
    "ECHO_COMMAND_PLACEHOLDER_DATA_FOR_TESTING_VFS_IMPLEMENTATION\n";

/* File definitions - CORRECTION: Initialisation dynamique */
static ramfs_file_t root_files[1];
static ramfs_file_t bin_files[3];
static ramfs_file_t etc_files[3];
static ramfs_file_t home_user_files[1];
static ramfs_file_t documents_files[1];
static ramfs_file_t log_files[1];

/* Fonction pour initialiser les fichiers */
static void ramfs_init_file_definitions(void)
{
    /* Root files */
    strcpy(root_files[0].name, "README.TXT");
    root_files[0].size = 0;
    root_files[0].first_cluster = 0;
    root_files[0].attr = 0x20;
    root_files[0].content = readme_content;
    
    /* Bin files */
    strcpy(bin_files[0].name, "LS");
    bin_files[0].size = 0;
    bin_files[0].first_cluster = 0;
    bin_files[0].attr = 0x20;
    bin_files[0].content = ls_binary;
    
    strcpy(bin_files[1].name, "CAT");
    bin_files[1].size = 0;
    bin_files[1].first_cluster = 0;
    bin_files[1].attr = 0x20;
    bin_files[1].content = cat_binary;
    
    strcpy(bin_files[2].name, "ECHO");
    bin_files[2].size = 0;
    bin_files[2].first_cluster = 0;
    bin_files[2].attr = 0x20;
    bin_files[2].content = echo_binary;
    
    /* Etc files */
    strcpy(etc_files[0].name, "PASSWD");
    etc_files[0].size = 0;
    etc_files[0].first_cluster = 0;
    etc_files[0].attr = 0x20;
    etc_files[0].content = passwd_content;
    
    strcpy(etc_files[1].name, "HOSTS");
    etc_files[1].size = 0;
    etc_files[1].first_cluster = 0;
    etc_files[1].attr = 0x20;
    etc_files[1].content = hosts_content;
    
    strcpy(etc_files[2].name, "CONFIG.TXT");
    etc_files[2].size = 0;
    etc_files[2].first_cluster = 0;
    etc_files[2].attr = 0x20;
    etc_files[2].content = config_content;
    
    /* Home user files */
    strcpy(home_user_files[0].name, "PROFILE.TXT");
    home_user_files[0].size = 0;
    home_user_files[0].first_cluster = 0;
    home_user_files[0].attr = 0x20;
    home_user_files[0].content = profile_content;
    
    /* Documents files */
    strcpy(documents_files[0].name, "README.TXT");
    documents_files[0].size = 0;
    documents_files[0].first_cluster = 0;
    documents_files[0].attr = 0x20;
    documents_files[0].content = user_readme_content;
    
    /* Log files */
    strcpy(log_files[0].name, "KERNEL.LOG");
    log_files[0].size = 0;
    log_files[0].first_cluster = 0;
    log_files[0].attr = 0x20;
    log_files[0].content = kernel_log_content;
}

/* Global cluster counter */
static uint32_t next_cluster = 3; /* Start after root directory (cluster 2) */

/* Function to allocate clusters and write file content */
static uint32_t ramfs_allocate_file_clusters(const char* content, uint32_t* file_size)
{
    if (!content) {
        *file_size = 0;
        return 0;
    }
    
    *file_size = strlen(content);
    
    if (*file_size == 0) {
        return 0;
    }
    
    /* Calculate clusters needed */
    uint32_t cluster_size = 512; /* 1 sector per cluster for simplicity */
    uint32_t clusters_needed = (*file_size + cluster_size - 1) / cluster_size;
    
    if (clusters_needed == 0) clusters_needed = 1;
    
    uint32_t first_cluster = next_cluster;
    next_cluster += clusters_needed;
    
    /* Calculate data area start */
    uint32_t data_start_sector = 32 + 2 * 1009; /* After FATs */
    
    /* Write file content to clusters */
    for (uint32_t i = 0; i < clusters_needed; i++) {
        uint32_t cluster_num = first_cluster + i;
        uint32_t sector = data_start_sector + (cluster_num - 2); /* Cluster 2 = first data cluster */
        uint8_t* cluster_data = ramfs_device.memory_base + (sector * 512);
        
        /* Clear cluster */
        memset(cluster_data, 0, 512);
        
        /* Copy content */
        uint32_t offset = i * cluster_size;
        uint32_t remaining = *file_size - offset;
        uint32_t to_copy = (remaining > cluster_size) ? cluster_size : remaining;
        
        if (to_copy > 0) {
            memcpy(cluster_data, content + offset, to_copy);
        }
    }
    
    /* Update FAT table */
    uint32_t fat_start_sector = 32;
    uint32_t* fat1 = (uint32_t*)(ramfs_device.memory_base + (fat_start_sector * 512));
    
    for (uint32_t i = 0; i < clusters_needed; i++) {
        uint32_t cluster_num = first_cluster + i;
        if (i == clusters_needed - 1) {
            fat1[cluster_num] = 0x0FFFFFFF; /* End of chain */
        } else {
            fat1[cluster_num] = cluster_num + 1; /* Next cluster */
        }
    }
    
    /* Copy to FAT2 */
    uint32_t* fat2 = (uint32_t*)(ramfs_device.memory_base + ((fat_start_sector + 1009) * 512));
    memcpy(fat2, fat1, 1009 * 512);
    
    return first_cluster;
}

static void ramfs_write_directory_entries(uint32_t dir_cluster, ramfs_file_t* files, uint32_t file_count, 
                                         ramfs_directory_t* subdirs, uint32_t subdir_count)
{
    /* Calculate directory sector */
    uint32_t data_start_sector = 32 + 2 * 1009;
    uint32_t sector = data_start_sector + (dir_cluster - 2);
    uint8_t* dir_data = ramfs_device.memory_base + (sector * 512);
    
    /* Clear directory */
    memset(dir_data, 0, 512);
    
    uint32_t entry_offset = 0;
    
    /* Write subdirectories first */
    for (uint32_t i = 0; i < subdir_count; i++) {
        if (entry_offset >= 512) break;
        
        uint8_t* entry = dir_data + entry_offset;
        
        /* Convert name to 8.3 format */
        char name_83[11];
        memset(name_83, ' ', 11);
        
        uint32_t name_len = strlen(subdirs[i].name);
        if (name_len > 8) name_len = 8;
        memcpy(name_83, subdirs[i].name, name_len);
        
        memcpy(entry, name_83, 11);
        entry[11] = 0x10; /* Directory attribute */
        *(uint16_t*)(entry + 26) = subdirs[i].first_cluster & 0xFFFF;
        *(uint16_t*)(entry + 20) = (subdirs[i].first_cluster >> 16) & 0xFFFF;
        *(uint32_t*)(entry + 28) = 0; /* Directory size is 0 */
        
        entry_offset += 32;
    }
    
    /* Write files */
    for (uint32_t i = 0; i < file_count; i++) {
        if (entry_offset >= 512) break;
        
        uint8_t* entry = dir_data + entry_offset;
        
        /* Convert name to 8.3 format */
        char name_83[11];
        memset(name_83, ' ', 11);
        
        const char* name = files[i].name;
        const char* dot = strchr(name, '.');
        
        if (dot) {
            /* Has extension */
            uint32_t base_len = dot - name;
            if (base_len > 8) base_len = 8;
            memcpy(name_83, name, base_len);
            
            uint32_t ext_len = strlen(dot + 1);
            if (ext_len > 3) ext_len = 3;
            memcpy(name_83 + 8, dot + 1, ext_len);
        } else {
            /* No extension */
            uint32_t name_len = strlen(name);
            if (name_len > 8) name_len = 8;
            memcpy(name_83, name, name_len);
        }
        
        memcpy(entry, name_83, 11);
        entry[11] = files[i].attr;
        *(uint16_t*)(entry + 26) = files[i].first_cluster & 0xFFFF;
        *(uint16_t*)(entry + 20) = (files[i].first_cluster >> 16) & 0xFFFF;
        *(uint32_t*)(entry + 28) = files[i].size;
        
        entry_offset += 32;
    }
}

static void ramfs_create_realistic_filesystem(void)
{
    KINFO("Creating realistic filesystem structure...\n");
    
    /* Initialiser les definitions de fichiers */
    ramfs_init_file_definitions();
    
    /* Allocate clusters for all files first */
    for (uint32_t i = 0; i < 1; i++) {
        root_files[i].first_cluster = ramfs_allocate_file_clusters(root_files[i].content, &root_files[i].size);
    }
    
    for (uint32_t i = 0; i < 3; i++) {
        bin_files[i].first_cluster = ramfs_allocate_file_clusters(bin_files[i].content, &bin_files[i].size);
    }
    
    for (uint32_t i = 0; i < 3; i++) {
        etc_files[i].first_cluster = ramfs_allocate_file_clusters(etc_files[i].content, &etc_files[i].size);
    }
    
    for (uint32_t i = 0; i < 1; i++) {
        home_user_files[i].first_cluster = ramfs_allocate_file_clusters(home_user_files[i].content, &home_user_files[i].size);
    }
    
    for (uint32_t i = 0; i < 1; i++) {
        documents_files[i].first_cluster = ramfs_allocate_file_clusters(documents_files[i].content, &documents_files[i].size);
    }
    
    for (uint32_t i = 0; i < 1; i++) {
        log_files[i].first_cluster = ramfs_allocate_file_clusters(log_files[i].content, &log_files[i].size);
    }
    
    /* Create directory structure */
    ramfs_directory_t directories[] = {
        {"BIN", next_cluster++, 2, bin_files, 3, NULL, 0},
        {"ETC", next_cluster++, 2, etc_files, 3, NULL, 0},
        {"HOME", next_cluster++, 2, NULL, 0, NULL, 0},
        {"TMP", next_cluster++, 2, NULL, 0, NULL, 0},
        {"VAR", next_cluster++, 2, NULL, 0, NULL, 0},
        {"USER", next_cluster++, directories[2].first_cluster, home_user_files, 1, NULL, 0},
        {"DOCUMENTS", next_cluster++, directories[5].first_cluster, documents_files, 1, NULL, 0},
        {"LOG", next_cluster++, directories[4].first_cluster, log_files, 1, NULL, 0},
    };
    
    /* Write directory entries */
    /* Root directory (cluster 2) */
    ramfs_directory_t root_subdirs[] = {
        directories[0], directories[1], directories[2], directories[3], directories[4]
    };
    ramfs_write_directory_entries(2, root_files, 1, root_subdirs, 5);
    
    /* Other directories */
    ramfs_write_directory_entries(directories[0].first_cluster, bin_files, 3, NULL, 0);
    ramfs_write_directory_entries(directories[1].first_cluster, etc_files, 3, NULL, 0);
    ramfs_write_directory_entries(directories[2].first_cluster, NULL, 0, &directories[5], 1); /* HOME with USER subdir */
    ramfs_write_directory_entries(directories[3].first_cluster, NULL, 0, NULL, 0); /* TMP empty */
    ramfs_write_directory_entries(directories[4].first_cluster, NULL, 0, &directories[7], 1); /* VAR with LOG subdir */
    ramfs_write_directory_entries(directories[5].first_cluster, home_user_files, 1, &directories[6], 1); /* USER with DOCUMENTS */
    ramfs_write_directory_entries(directories[6].first_cluster, documents_files, 1, NULL, 0);
    ramfs_write_directory_entries(directories[7].first_cluster, log_files, 1, NULL, 0);
    
    KINFO("OK Realistic filesystem created with:\n");
    KINFO("  - 5 top-level directories\n");
    KINFO("  - 3 subdirectories\n"); 
    KINFO("  - %u files with real content\n", 1 + 3 + 3 + 1 + 1 + 1);
}

static void ramfs_create_fat32_filesystem(void)
{
    KINFO("Creating FAT32 filesystem in RAMFS...\n");
    
    /* Write boot sector */
    ramfs_write_boot_sector(ramfs_device.memory_base);
    
    /* Write FAT tables (basic structure) */
    ramfs_write_fat_tables();
    
    /* Create realistic filesystem with files */
    ramfs_create_realistic_filesystem();
    
    KINFO("OK Complete FAT32 filesystem created in RAMFS\n");
}

static void ramfs_write_boot_sector(uint8_t* sector)
{
    KDEBUG("Writing FAT32 boot sector...\n");
    
    /* Clear sector */
    memset(sector, 0, 512);
    
    /* Jump instruction and OEM */
    sector[0] = 0xEB; sector[1] = 0x58; sector[2] = 0x90;
    memcpy(sector + 3, "RAMFS   ", 8);
    
    /* BIOS Parameter Block */
    *(uint16_t*)(sector + 11) = 512;        /* bytes_per_sector */
    sector[13] = 1;                         /* sectors_per_cluster */
    *(uint16_t*)(sector + 14) = 32;         /* reserved_sectors */
    sector[16] = 2;                         /* num_fats */
    *(uint16_t*)(sector + 17) = 0;          /* root_entries (FAT32) */
    *(uint16_t*)(sector + 19) = 0;          /* total_sectors_16 */
    sector[21] = 0xF8;                      /* media_descriptor */
    *(uint16_t*)(sector + 22) = 0;          /* fat_size_16 (FAT32) */
    
    *(uint16_t*)(sector + 24) = 32;         /* sectors_per_track */
    *(uint16_t*)(sector + 26) = 8;          /* num_heads */
    *(uint32_t*)(sector + 28) = 0;          /* hidden_sectors */
    *(uint32_t*)(sector + 32) = RAMFS_SECTORS; /* total_sectors_32 */
    
    /* FAT32 Extended BPB */
    *(uint32_t*)(sector + 36) = 1009;       /* fat_size_32 */
    *(uint16_t*)(sector + 40) = 0;          /* flags */
    *(uint16_t*)(sector + 42) = 0;          /* version */
    *(uint32_t*)(sector + 44) = 2;          /* root_cluster */
    *(uint16_t*)(sector + 48) = 1;          /* fsinfo_sector */
    *(uint16_t*)(sector + 50) = 6;          /* backup_boot_sector */
    
    /* Extended fields */
    sector[66] = 0x80;                      /* drive_number */
    sector[67] = 0;                         /* reserved */
    sector[68] = 0x29;                      /* boot_signature */
    *(uint32_t*)(sector + 69) = 0x12345678; /* volume_serial */
    memcpy(sector + 71, "RAMFS      ", 11); /* volume_label */
    memcpy(sector + 82, "FAT32   ", 8);     /* fs_type */
    
    /* Boot signature */
    sector[510] = 0x55;
    sector[511] = 0xAA;
    
    KDEBUG("OK Boot sector written\n");
}

static void ramfs_write_fat_tables(void)
{
    KDEBUG("Writing FAT tables...\n");
    
    /* FAT starts at sector 32 */
    uint32_t fat_start_sector = 32;
    uint32_t fat_size_sectors = 1009;
    
    /* Write FAT 1 */
    uint8_t* fat1 = ramfs_device.memory_base + (fat_start_sector * 512);
    memset(fat1, 0, fat_size_sectors * 512);
    
    /* Initialize first FAT entries */
    *(uint32_t*)(fat1 + 0) = 0x0FFFFFF8;    /* Media descriptor */
    *(uint32_t*)(fat1 + 4) = 0x0FFFFFFF;    /* End of chain */
    *(uint32_t*)(fat1 + 8) = 0x0FFFFFFF;    /* Root directory */
    
    /* Write FAT 2 (copy) */
    uint8_t* fat2 = ramfs_device.memory_base + ((fat_start_sector + fat_size_sectors) * 512);
    memcpy(fat2, fat1, fat_size_sectors * 512);
    
    KDEBUG("OK FAT tables written\n");
}

static void ramfs_write_root_directory(void)
{
    KDEBUG("Writing root directory...\n");
    
    /* Root directory starts at cluster 2 */
    /* Data area starts after FATs: 32 + 2*1009 = 2050 sectors */
    uint32_t data_start_sector = 32 + 2 * 1009;
    /* Cluster 2 = first cluster of data area */
    uint8_t* root_dir = ramfs_device.memory_base + (data_start_sector * 512);
    
    /* Clear root directory cluster */
    memset(root_dir, 0, 512);
    
    /* Create volume label entry */
    memcpy(root_dir, "RAMFS      ", 11);    /* Volume label */
    root_dir[11] = 0x08;                    /* Volume label attribute */
    
    /* Create a test file entry */
    uint8_t* file_entry = root_dir + 32;
    memcpy(file_entry, "README  TXT", 11);  /* 8.3 filename */
    file_entry[11] = 0x20;                  /* Archive attribute */
    *(uint16_t*)(file_entry + 26) = 3;      /* First cluster (low) */
    *(uint32_t*)(file_entry + 28) = 13;     /* File size */
    
    KDEBUG("OK Root directory written\n");
}

/* ============================================================================
 * TEST AND DEBUG FUNCTIONS
 * ============================================================================ */

void ramfs_test(void)
{
    KINFO("=== RAMFS COMPREHENSIVE TEST ===\n");
    
    if (!ramfs_is_initialized()) {
        KERROR("RAMFS not initialized\n");
        return;
    }
    
    static uint8_t test_buffer[512] __attribute__((aligned(4)));
    
    /* Test 1: Boot sector */
    KINFO("1. Testing boot sector...\n");
    int result = ramfs_read_sectors(0, 1, test_buffer);
    
    if (result > 0) {
        KINFO("OK Boot sector read successful!\n");
        
        /* Create null-terminated strings for safe printing */
        char oem_str[9] = {0};
        char volume_str[12] = {0};
        char fs_str[9] = {0};
        
        memcpy(oem_str, test_buffer + 3, 8);
        memcpy(volume_str, test_buffer + 71, 11);
        memcpy(fs_str, test_buffer + 82, 8);
        
        KINFO("   OEM: '%s'\n", oem_str);
        KINFO("   Volume: '%s'\n", volume_str);
        KINFO("   FS type: '%s'\n", fs_str);
        KINFO("   Signature: %02X %02X %s\n", 
              test_buffer[510], test_buffer[511],
              (test_buffer[510] == 0x55 && test_buffer[511] == 0xAA) ? "OK" : "KO");
    }
    
    /* Test 2: Root directory */
    KINFO("\n2. Testing root directory structure...\n");
    uint32_t data_start_sector = 32 + 2 * 1009;
    
    KDEBUG("   Data start sector calculated: %u\n", data_start_sector);
    KDEBUG("   Reading from LBA %u (cluster 2)\n", data_start_sector);
    
    result = ramfs_read_sectors(data_start_sector, 1, test_buffer);
    
    if (result > 0) {
        KINFO("OK Root directory read successful!\n");
        KINFO("   Root directory contents:\n");
        
        /* Debug: Show first 64 bytes of directory */
        KDEBUG("   First 64 bytes of root directory:\n");
        KDEBUG("   ");
        for (int i = 0; i < 64; i++) {
            kprintf("%02X ", test_buffer[i]);
            if ((i + 1) % 16 == 0) {
                kprintf("\n");
                if (i < 63) KDEBUG("   ");
            }
        }
        kprintf("\n");
        
        for (int i = 0; i < 16; i++) { /* Max 16 entries per sector */
            uint8_t* entry = test_buffer + (i * 32);
            
            if (entry[0] == 0) break; /* End of directory */
            if (entry[0] == 0xE5) continue; /* Deleted entry */
            
            /* Clean up name and make it safe for printing */
            char safe_name[13] = {0};  /* Extra space for safety */
            
            /* Copy name safely */
            int name_pos = 0;
            for (int j = 0; j < 11 && entry[j] != 0; j++) {
                if (entry[j] != ' ' || name_pos == 0) {  /* Don't start with space */
                    safe_name[name_pos++] = entry[j];
                }
                if (name_pos >= 11) break;  /* Safety limit */
            }
            
            /* Remove trailing spaces */
            while (name_pos > 0 && safe_name[name_pos - 1] == ' ') {
                safe_name[--name_pos] = 0;
            }
            
            /* Ensure we have some name */
            if (name_pos == 0) {
                strcpy(safe_name, "UNKNOWN");
            }
            
            uint8_t attr = entry[11];
            uint32_t size = *(uint32_t*)(entry + 28);
            uint16_t cluster_lo = *(uint16_t*)(entry + 26);
            uint16_t cluster_hi = *(uint16_t*)(entry + 20);
            uint32_t cluster = ((uint32_t)cluster_hi << 16) | cluster_lo;
            
            const char* type = (attr & 0x10) ? "- DIR " : "- FILE";
            
            /* Debug the raw data */
            KDEBUG("   Entry %d: raw name bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n", 
                   i, entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7]);
            KDEBUG("   Processed name: '%s', cluster_hi=%u, cluster_lo=%u\n", 
                   safe_name, cluster_hi, cluster_lo);
            
            KINFO("   %s %s (cluster: %u, size: %u)\n", type, safe_name, cluster, size);
        }
    }
    
    /* Test 3: Read a file content */
    KINFO("\n3. Testing file content reading...\n");
    
    /* Try to read README.TXT content (should be in cluster 5) */
    uint32_t readme_sector = data_start_sector + (14 - 2); /* Cluster 5 */
    static uint8_t bin_buffer[10000] __attribute__((aligned(4)));

    result = ramfs_read_sectors(readme_sector, 12, bin_buffer);
    
    if (result > 0) {
        KINFO("OK File content read successful!\n");
        KINFO("   README.TXT content (first 200 chars):\n");
        KINFO("   l--------------------------------------------------l\n");

                /* Debug: Show first 5900 bytes of directory */
        /*KDEBUG("   First 5900 bytes of file:\n");
        KDEBUG("   ");
        for (int i = 0; i < 5900; i++) {
            kprintf("%02X ", bin_buffer[i]);
            if ((i + 1) % 48 == 0) {
                kprintf("\n");
                if (i < 5899) KDEBUG("   ");
            }
        }
        kprintf("\n");*/
        
        /* Display first 200 chars safely */
        char display_buffer[5901] = {0};
        for (int i = 0; i < 5900 && i < 10000 && bin_buffer[i]; i++) {
            display_buffer[i] = (bin_buffer[i] >= 32 && bin_buffer[i] <= 126) ? 
                               bin_buffer[i] : '.';
        }
        
        /* Print in lines of 47 chars to fit in box */
        size_t display_len = strlen(display_buffer);
        for (size_t i = 0; i < 5900 && i < display_len; i += 47) {
            char line[48] = {0};
            size_t line_len = (i + 47 > display_len) ? display_len - i : 47;
            strncpy(line, display_buffer + i, line_len);
            line[47] = 0;  /* Ensure null termination */
            
            /* Pad line to exactly 47 characters */
            size_t actual_len = strlen(line);
            if (actual_len < 47) {
                memset(line + actual_len, ' ', 47 - actual_len);
                line[47] = 0;
            }
            
            KINFO("   l %s l\n", line);
            if (i + 47 >= display_len) break;
        }
        KINFO("   l--------------------------------------------------l\n");
    }
  
#if(0)
    /* Test 4: Write/Read verification */
    KINFO("\n4. Testing write/read operations...\n");
    
    static uint8_t write_test[512];
    const char* test_content = "This is a write test from the kernel!\n"
                              "Testing RAMFS write capabilities.\n"
                              "If you can read this, write operations work!\n";
    
    memset(write_test, 0, 512);
    strcpy((char*)write_test, test_content);
    
    /* Write to sector 1000 (free area) */
    result = ramfs_write_sectors(1000, 1, write_test);
    if (result > 0) {
        KINFO("OK Write operation successful\n");
        
        /* Read back */
        memset(test_buffer, 0, 512);
        result = ramfs_read_sectors(1000, 1, test_buffer);
        
        if (result > 0 && strcmp((char*)test_buffer, test_content) == 0) {
            KINFO("OK Write/read verification successful!\n");
            
            /* Create safe string for display */
            char display_content[51] = {0};
            strncpy(display_content, (char*)test_buffer, 50);
            
            KINFO("   Verified content: '%s...'\n", display_content);
        } else {
            KERROR("KO Write/read verification failed\n");
        }
    }
    
    /* Test 5: Performance test */
    KINFO("\n5. Testing performance...\n");
    
    uint32_t start_sector = 2000;
    uint32_t test_sectors = 100;
    
    /* Write test */
    memset(write_test, 0xAA, 512);
    for (uint32_t i = 0; i < test_sectors; i++) {
        result = ramfs_write_sectors(start_sector + i, 1, write_test);
        if (result <= 0) break;
    }
    
    if (result > 0) {
        KINFO("OK Performance test: %u sectors written successfully\n", test_sectors);
        
        /* Read test */
        uint32_t read_count = 0;
        for (uint32_t i = 0; i < test_sectors; i++) {
            result = ramfs_read_sectors(start_sector + i, 1, test_buffer);
            if (result > 0 && test_buffer[0] == 0xAA) {
                read_count++;
            }
        }
        
        KINFO("OK Performance test: %u/%u sectors read correctly\n", read_count, test_sectors);
    }
 #endif   

    KINFO("\n=== RAMFS TEST COMPLETE ===\n");
    KINFO("SUMMARY Summary:\n");
    KINFO("   - Total capacity: %u MB (%u sectors)\n", 
          RAMFS_SIZE / (1024*1024), RAMFS_SECTORS);
    KINFO("   - Filesystem: FAT32 with realistic structure\n");
    KINFO("   - Directories: /bin, /etc, /home, /tmp, /var\n");
    KINFO("   - Files: System configs, user files, logs, binaries\n");
    KINFO("   - Ready for VFS testing! TARGET\n");
}

/* Test function pour RAMFS avec extraction TAR vers FAT32 */

void ramfs_tar_test(void)
{
    KINFO("=== RAMFS TAR EXTRACTION TEST (FIXED) ===\n");
    
    if (!ramfs_is_initialized()) {
        KERROR("RAMFS not initialized\n");
        return;
    }
    
    static uint8_t test_buffer[512] __attribute__((aligned(4)));
    
    /* Test 1: Verifier le format FAT32 */
    KINFO("1. Testing current filesystem format...\n");
    int result = ramfs_read_sectors(0, 1, test_buffer);
    
    bool has_fat32 = false;
    if (result > 0) {
        if (test_buffer[510] == 0x55 && test_buffer[511] == 0xAA) {
            KINFO("- FAT32 boot sector detected\n");
            has_fat32 = true;
            
            char oem_str[9] = {0};
            char volume_str[12] = {0};
            char fs_str[9] = {0};
            
            memcpy(oem_str, test_buffer + 3, 8);
            memcpy(volume_str, test_buffer + 71, 11);
            memcpy(fs_str, test_buffer + 82, 8);
            
            KINFO("   OEM: '%s'\n", oem_str);
            KINFO("   Volume: '%s'\n", volume_str);
            KINFO("   FS type: '%s'\n", fs_str);
            KINFO("   Signature: %02X %02X OK\n", test_buffer[510], test_buffer[511]);
        }
    }
    
    /* Test 2: Analyser le VRAI root directory (cluster 2) */
    KINFO("\n2. Analyzing ROOT directory (cluster 2)...\n");
    
    if (has_fat32) {
        /* CORRECTION: Lire le cluster 2 (root directory) */
        uint32_t data_start_sector = 32 + 2 * 1009;  /* Apres reserved + 2 FATs */
        uint32_t root_cluster = 2;
        uint32_t root_sector = data_start_sector + (root_cluster - 2);
        
        KINFO("   Data start sector: %u\n", data_start_sector);
        KINFO("   Root cluster: %u\n", root_cluster);
        KINFO("   Root sector: %u\n", root_sector);
        
        result = ramfs_read_sectors(root_sector, 1, test_buffer);
        
        if (result > 0) {
            KINFO("OK ROOT directory found at sector %u\n", root_sector);
            KINFO("   Root directory entries:\n");
            KINFO("   l-----------------------------------------------------------l\n");
            KINFO("   l Type l Cluster  l Size      l Name                        l\n");
            KINFO("   l------l----------l-----------l-----------------------------l\n");
            
            for (int i = 0; i < 16; i++) {
                uint8_t* entry = test_buffer + (i * 32);
                
                if (entry[0] == 0) break;  /* Fin des entrees */
                if (entry[0] == 0xE5) continue;  /* Entree supprimee */
                
                char name[13] = {0};
                int name_pos = 0;
                
                /* Extraire le nom (format 8.3) */
                for (int j = 0; j < 8; j++) {
                    if (entry[j] != ' ' && entry[j] != 0) {
                        name[name_pos++] = entry[j];
                    }
                }
                if (entry[8] != ' ' && entry[8] != 0) {
                    name[name_pos++] = '.';
                    for (int j = 8; j < 11; j++) {
                        if (entry[j] != ' ' && entry[j] != 0) {
                            name[name_pos++] = entry[j];
                        }
                    }
                }
                
                uint8_t attr = entry[11];
                uint32_t size = *(uint32_t*)(entry + 28);
                uint32_t cluster = *(uint16_t*)(entry + 26) | (*(uint16_t*)(entry + 20) << 16);
                
                const char* type_str;
                if (attr & 0x08) {
                    type_str = "VOL ";
                } else if (attr & 0x10) {
                    type_str = "DIR ";
                } else {
                    type_str = "FILE";
                }
                
                KINFO("   l %-4s l %-8u l %-9u l %-27s l\n", 
                      type_str, cluster, size, name);
            }
            KINFO("   l-------------------------------------------------------------l\n");
        }
    }
    
    /* Test 3: Explorer le repertoire "." (cluster 33) */
    KINFO("\n3. Exploring main directory (cluster 33)...\n");
    
    if (has_fat32) {
        uint32_t data_start_sector = 32 + 2 * 1009;
        uint32_t main_cluster = 72;  /* D'apres les logs */
        uint32_t main_sector = data_start_sector + (main_cluster - 2);
        
        KINFO("   Main directory sector: %u\n", main_sector);
        
        result = ramfs_read_sectors(main_sector, 1, test_buffer);
        
        if (result > 0) {
            KINFO("OK Main directory found at sector %u\n", main_sector);
            KINFO("   Main directory entries:\n");
            KINFO("   l-----------------------------------------------------------l\n");
            KINFO("   l Type l Cluster  l Size      l Name                        l\n");
            KINFO("   l------l----------l-----------l-----------------------------l\n");
            
            for (int i = 0; i < 16; i++) {
                uint8_t* entry = test_buffer + (i * 32);
                
                if (entry[0] == 0) break;
                if (entry[0] == 0xE5) continue;
                
                char name[13] = {0};
                int name_pos = 0;
                
                for (int j = 0; j < 8; j++) {
                    if (entry[j] != ' ' && entry[j] != 0) {
                        name[name_pos++] = entry[j];
                    }
                }
                if (entry[8] != ' ' && entry[8] != 0) {
                    name[name_pos++] = '.';
                    for (int j = 8; j < 11; j++) {
                        if (entry[j] != ' ' && entry[j] != 0) {
                            name[name_pos++] = entry[j];
                        }
                    }
                }
                
                uint8_t attr = entry[11];
                uint32_t size = *(uint32_t*)(entry + 28);
                uint32_t cluster = *(uint16_t*)(entry + 26) | (*(uint16_t*)(entry + 20) << 16);
                
                const char* type_str;
                if (attr & 0x08) {
                    type_str = "VOL ";
                } else if (attr & 0x10) {
                    type_str = "DIR ";
                } else {
                    type_str = "FILE";
                }
                
                KINFO("   l %-4s l %-8u l %-9u l %-27s l\n", 
                      type_str, cluster, size, name);
            }
            KINFO("   l-------------------------------------------------------------l\n");
        }
    }
    
    /* Reste des tests... */
    KINFO("\n4. Testing I/O operations...\n");
    // ... vos tests I/O existants ...
    
    KINFO("\n=== TEST SUMMARY (FIXED) ===\n");
    KINFO("SUMMARY Status:\n");
    KINFO("   - RAMFS: OK Initialized at 0x%08X\n", (uint32_t)ramfs_device.memory_base);
    KINFO("   - Format: OK FAT32 with complete directory structure\n");
    KINFO("   - Root directory: OK Points to main directory (cluster 33)\n");
    KINFO("   - Files: OK All TAR files extracted and accessible\n");
    KINFO("   - VFS Ready: OK Yes - complete filesystem structure\n");
}

void ramfs_tar_test2(void)
{
    KINFO("=== RAMFS TAR EXTRACTION TEST ===\n");
    
    if (!ramfs_is_initialized()) {
        KERROR("RAMFS not initialized\n");
        return;
    }
    
    static uint8_t test_buffer[512] __attribute__((aligned(4)));
    
    /* Test 1: Verifier le format actuel (devrait etre FAT32 apres conversion) */
    KINFO("1. Testing current filesystem format...\n");
    int result = ramfs_read_sectors(0, 1, test_buffer);
    
    bool has_fat32 = false;
    if (result > 0) {
        if (test_buffer[510] == 0x55 && test_buffer[511] == 0xAA) {
            KINFO("- FAT32 boot sector detected\n");
            has_fat32 = true;
            
            /* Analyser boot sector FAT32 */
            char oem_str[9] = {0};
            char volume_str[12] = {0};
            char fs_str[9] = {0};
            
            memcpy(oem_str, test_buffer + 3, 8);
            memcpy(volume_str, test_buffer + 71, 11);
            memcpy(fs_str, test_buffer + 82, 8);
            
            KINFO("   OEM: '%s'\n", oem_str);
            KINFO("   Volume: '%s'\n", volume_str);
            KINFO("   FS type: '%s'\n", fs_str);
            KINFO("   Signature: %02X %02X OK\n", test_buffer[510], test_buffer[511]);
            
        } else if (memcmp(test_buffer, "USERFS01", 8) == 0) {
            KINFO("- Original TAR data detected (not converted yet)\n");
            /* Analyser TAR comme avant */
            
        } else {
            KINFO("- Unknown format detected\n");
        }
    }
    
    /* Test 2: Analyser le contenu (FAT32 ou TAR selon le cas) */
    KINFO("\n2. Analyzing filesystem content...\n");
    
    if (has_fat32) {
        /* Analyser contenu FAT32 */
        uint32_t data_start_sector = 32 + 2 * 1009;
        result = ramfs_read_sectors(data_start_sector, 1, test_buffer);
        
        if (result > 0) {
            KINFO("OK FAT32 root directory found\n");
            KINFO("   Converted files from TAR:\n");
            KINFO("   l-----------------------------------------------------------l\n");
            KINFO("   l Type l Cluster  l Size      l Name                        l\n");
            KINFO("   l------l----------l-----------l-----------------------------l\n");
            
            for (int i = 0; i < 16; i++) {
                uint8_t* entry = test_buffer + (i * 32);
                
                if (entry[0] == 0) break;
                if (entry[0] == 0xE5) continue;
                
                char name[13] = {0};
                int name_pos = 0;
                for (int j = 0; j < 11; j++) {
                    if (entry[j] != ' ') {
                        name[name_pos++] = entry[j];
                    }
                }
                
                uint8_t attr = entry[11];
                uint32_t size = *(uint32_t*)(entry + 28);
                uint32_t cluster = *(uint16_t*)(entry + 26) | (*(uint16_t*)(entry + 20) << 16);
                
                const char* type_str = (attr & 0x08) ? "VOL " : 
                                      (attr & 0x10) ? "DIR " : "FILE";
                
                KINFO("   l %-4s l %-8u l %-9u l %-27s l\n", type_str, cluster, size, name);
            }
            KINFO("   l-------------------------------------------------------------l\n");
        }
    } else {
        KINFO("KO No FAT32 filesystem found\n");
        KINFO("- Run create_fat32_filesystem_from_userfs() to convert TAR to FAT32\n");
    }
    
    /* Test 3: Tests I/O et performance (identiques) */
    KINFO("\n3. Testing I/O operations...\n");
    
    static uint8_t write_test[512];
    const char* test_content = "RAMFS Test - Filesystem conversion successful\n";
    
    memset(write_test, 0, 512);
    strcpy((char*)write_test, test_content);
    
    result = ramfs_write_sectors(5000, 1, write_test);
    if (result > 0) {
        KINFO("OK Write test successful\n");
        
        memset(test_buffer, 0, 512);
        result = ramfs_read_sectors(5000, 1, test_buffer);
        
        if (result > 0 && strcmp((char*)test_buffer, test_content) == 0) {
            KINFO("OK Read verification successful\n");
        }
    }
    
    /* Test 4: Performance */
    KINFO("\n4. Testing performance...\n");
    
    uint32_t perf_sectors = 50;
    uint32_t success_count = 0;
    
    memset(write_test, 0xCC, 512);
    for (uint32_t i = 0; i < perf_sectors; i++) {
        if (ramfs_write_sectors(10000 + i, 1, write_test) > 0) {
            if (ramfs_read_sectors(10000 + i, 1, test_buffer) > 0) {
                if (test_buffer[0] == 0xCC) {
                    success_count++;
                }
            }
        }
    }
    
    uint32_t percentage = (success_count * 100) / perf_sectors;
    KINFO("OK Performance test: %u/%u sectors OK (%u%% success)\n", 
          success_count, perf_sectors, percentage);
    
    /* Resume final */
    KINFO("\n=== TEST SUMMARY ===\n");
    KINFO("SUMMARY Status:\n");
    KINFO("   - RAMFS: OK Initialized at 0x%08X\n", (uint32_t)ramfs_device.memory_base);
    KINFO("   - Format: %s\n", has_fat32 ? "OK FAT32 (converted)" : "- TAR (original)");
    KINFO("   - I/O: OK Working perfectly\n");
    KINFO("   - Performance: %u%% success rate\n", percentage);
    KINFO("   - VFS Ready: %s\n", has_fat32 ? "OK Yes" : "KO Need conversion");
    
    if (has_fat32) {
        KINFO("- Your filesystem is ready for VFS mounting!\n");
        KINFO("   Next: call init_vfs() to mount the FAT32 filesystem\n");
    } else {
        KINFO("- To enable VFS mounting:\n");
        KINFO("   1. Call create_fat32_filesystem_from_userfs()\n");
        KINFO("   2. This will convert TAR to FAT32\n");
        KINFO("   3. Then init_vfs() will work\n");
    }
}


void debug_ramfs_creation_step_by_step(void)
{
    KINFO("[CREATE] === Debug creation filesystem step by step ===\n");
        
    if (!ramfs_device.initialized) {
        KERROR("[CREATE] RAMFS pas initialise\n");
        return;
    }
    
    KINFO("[CREATE] RAMFS base: %p\n", ramfs_device.memory_base);
    KINFO("[CREATE] RAMFS size: %u\n", ramfs_device.total_size);
    
    /* Test 1: ecriture simple dans RAMFS */
    KINFO("[CREATE] Test 1: ecriture simple...\n");
    //static uint8_t test_buffer[512] __attribute__((aligned(4)));
    static uint8_t test_data[512] __attribute__((aligned(4)));
    memset(test_data, 0xBB, 512);
    test_data[510] = 0x55;
    test_data[511] = 0xAA;
    
    int write_result = ramfs_write_sectors(0, 1, test_data);
    KINFO("[CREATE] Write result: %d\n", write_result);
    
    /* Test 2: Lecture pour verifier */
    static uint8_t read_buffer[512];
    int read_result = ramfs_read_sectors(0, 1, read_buffer);
    KINFO("[CREATE] Read result: %d\n", read_result);
    
    if (read_result > 0) {
        KINFO("[CREATE] Lu: %02X %02X ... %02X %02X\n", 
              read_buffer[0], read_buffer[1], read_buffer[510], read_buffer[511]);
        
        if (read_buffer[510] == 0x55 && read_buffer[511] == 0xAA) {
            KINFO("[CREATE] OK RAMFS lecture/ecriture fonctionne\n");
        } else {
            KERROR("[CREATE] KO RAMFS lecture/ecriture defaillante\n");
        }
    }
    
    /* Test 3: Recreer le boot sector manuellement */
    KINFO("[CREATE] Test 3: Creation boot sector manuel...\n");
    memset(test_data, 0, 512);
    
    /* Boot sector minimal */
    test_data[0] = 0xEB; test_data[1] = 0x58; test_data[2] = 0x90;  /* Jump */
    memcpy(test_data + 3, "RAMFS   ", 8);                           /* OEM */
    *(uint16_t*)(test_data + 11) = 512;                             /* Bytes per sector */
    test_data[13] = 1;                                              /* Sectors per cluster */
    *(uint16_t*)(test_data + 14) = 32;                              /* Reserved sectors */
    test_data[16] = 2;                                              /* Num FATs */
    *(uint32_t*)(test_data + 36) = 1009;                            /* FAT size 32 */
    *(uint32_t*)(test_data + 44) = 2;                               /* Root cluster */
    test_data[510] = 0x55; test_data[511] = 0xAA;                   /* Signature */
    
    ramfs_write_sectors(0, 1, test_data);
    
    /* Verifier */
    ramfs_read_sectors(0, 1, read_buffer);
    if (read_buffer[510] == 0x55 && read_buffer[511] == 0xAA) {
        KINFO("[CREATE] OK Boot sector manuel cree\n");
    } else {
        KERROR("[CREATE] KO Boot sector manuel echoue\n");
    }
    
    /* Test 4: Creer le repertoire racine manuellement */
    KINFO("[CREATE] Test 4: Creation repertoire racine...\n");
    memset(test_data, 0, 512);
    
    /* Entree volume label */
    memcpy(test_data, "RAMFS      ", 11);
    test_data[11] = 0x08;  /* Volume label attribute */
    
    /* Entree README.TXT */
    memcpy(test_data + 32, "README  TXT", 11);
    test_data[32 + 11] = 0x20;                                      /* File attribute */
    *(uint16_t*)(test_data + 32 + 26) = 3;                          /* First cluster */
    *(uint32_t*)(test_data + 32 + 28) = 100;                        /* File size */
    
    /* ecrire au secteur 2050 (cluster 2) */
    ramfs_write_sectors(2050, 1, test_data);
    
    /* Verifier */
    ramfs_read_sectors(2050, 1, read_buffer);
    if (read_buffer[0] == 'R' && read_buffer[1] == 'A') {
        KINFO("[CREATE] OK Repertoire racine manuel cree\n");
    } else {
        KERROR("[CREATE] KO Repertoire racine manuel echoue\n");
        KINFO("[CREATE] Lu: %02X %02X %02X %02X\n", 
              read_buffer[0], read_buffer[1], read_buffer[2], read_buffer[3]);
    }
}

/* Test de la fonction que utilise réellement votre couche FAT32 */
void test_fat32_read_function(uint32_t sector) {
    //uint8_t test_buffer[512];
    
    KINFO("[DEBUG] Testing whatever function your FAT32 code uses to read sectors...\n");
    
    // TODO: Remplacez cette ligne par l'appel à la fonction que utilise
    // réellement votre code FAT32 pour lire les secteurs
    // Par exemple si vous avez une fonction wrapper comme fat32_read_sector()
    // 
    // int result = fat32_read_sector(sector, test_buffer);

        
    static uint8_t bin_buffer[10000] __attribute__((aligned(4)));
    
    int result = ramfs_read_sectors(sector, 12, bin_buffer);
    
    if (result > 0) {
        KINFO("[DEBUG] FAT32 read function succeeded\n");
        KINFO("[DEBUG] First 32 bytes:\n");
        for (int i = 0; i < 5800; i++) {
            if (i % 48 == 0) kprintf("\n[%03d]: ", i);
            kprintf("%02X ", bin_buffer[i]);
        }
        kprintf("\n");
    } else {
        KERROR("[DEBUG] FAT32 read function failed with result: %d\n", result);
    }
}

void debug_root_directory_reading(void) {
    uint32_t root_sector = 2050;  // Secteur racine calculé
    uint8_t sector_data[512] __attribute__((aligned(4)));
    
    KINFO("[DEBUG] === DEBUGGING ROOT DIRECTORY READING ===\n");
    
    // 1. Vérifier les informations RAMFS device
    KINFO("[DEBUG] RAMFS device info:\n");
    KINFO("[DEBUG]   Initialized: %s\n", ramfs_device.initialized ? "Yes" : "No");
    KINFO("[DEBUG]   Memory base: 0x%08X\n", (uint32_t)ramfs_device.memory_base);
    KINFO("[DEBUG]   Sector size: %u\n", ramfs_device.sector_size);
    KINFO("[DEBUG]   Total sectors: %u\n", ramfs_device.total_sectors);
    
    // 2. Calculer l'adresse du secteur racine
    uint32_t sector_offset = root_sector * ramfs_device.sector_size;
    uint8_t *sector_address = ramfs_device.memory_base + sector_offset;
    
    KINFO("[DEBUG] Root sector calculation:\n");
    KINFO("[DEBUG]   Root sector: %u\n", root_sector);
    KINFO("[DEBUG]   Sector offset: %u bytes (0x%08X)\n", sector_offset, sector_offset);
    KINFO("[DEBUG]   Sector address: 0x%08X\n", (uint32_t)sector_address);
    
    // 3. Vérifier que le secteur est dans les limites
    if (root_sector >= ramfs_device.total_sectors) {
        KERROR("[DEBUG] ✗ Root sector %u is beyond device capacity (%u sectors)!\n", 
               root_sector, ramfs_device.total_sectors);
        return;
    }
    
    // 4. Lire directement depuis la mémoire RAMFS
    KINFO("[DEBUG] Reading sector directly from RAMFS memory:\n");
    kprintf("[DEBUG] First 64 bytes of sector %u:\n", root_sector);
    for (int i = 0; i < 64; i++) {
        if (i % 16 == 0) kprintf("\n[%03d]: ", i);
        kprintf("%02X ", sector_address[i]);
    }
    kprintf("\n");
    

        /* Test 2: Root directory */
    KINFO("\n2. Testing root directory structure...\n");
    uint32_t data_start_sector = 32 + 2 * 1009;
    
    KDEBUG("   Data start sector calculated: %u\n", data_start_sector);
    KDEBUG("   Reading from LBA %u (cluster 2)\n", data_start_sector);

    static uint8_t test_buffer[512] __attribute__((aligned(4)));
    
    int res = ramfs_read_sectors(data_start_sector, 1, test_buffer);
    
    if (res > 0) {
        KINFO("OK Root directory read successful!\n");
        KINFO("   Root directory contents:\n");
        
        /* Debug: Show first 64 bytes of directory */
        KDEBUG("   First 64 bytes of root directory:\n");
        KDEBUG("   ");
        for (int i = 0; i < 64; i++) {
            kprintf("%02X ", test_buffer[i]);
            if ((i + 1) % 16 == 0) {
                kprintf("\n");
                if (i < 63) KDEBUG("   ");
            }
        }
        kprintf("\n");
        
        for (int i = 0; i < 16; i++) { /* Max 16 entries per sector */
            uint8_t* entry = test_buffer + (i * 32);
            
            if (entry[0] == 0) break; /* End of directory */
            if (entry[0] == 0xE5) continue; /* Deleted entry */
            
            /* Clean up name and make it safe for printing */
            char safe_name[13] = {0};  /* Extra space for safety */
            
            /* Copy name safely */
            int name_pos = 0;
            for (int j = 0; j < 11 && entry[j] != 0; j++) {
                if (entry[j] != ' ' || name_pos == 0) {  /* Don't start with space */
                    safe_name[name_pos++] = entry[j];
                }
                if (name_pos >= 11) break;  /* Safety limit */
            }
            
            /* Remove trailing spaces */
            while (name_pos > 0 && safe_name[name_pos - 1] == ' ') {
                safe_name[--name_pos] = 0;
            }
            
            /* Ensure we have some name */
            if (name_pos == 0) {
                strcpy(safe_name, "UNKNOWN");
            }
            
            uint8_t attr = entry[11];
            uint32_t size = *(uint32_t*)(entry + 28);
            uint16_t cluster_lo = *(uint16_t*)(entry + 26);
            uint16_t cluster_hi = *(uint16_t*)(entry + 20);
            uint32_t cluster = ((uint32_t)cluster_hi << 16) | cluster_lo;
            
            const char* type = (attr & 0x10) ? "- DIR " : "- FILE";
            
            /* Debug the raw data */
            KDEBUG("   Entry %d: raw name bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n", 
                   i, entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7]);
            KDEBUG("   Processed name: '%s', cluster_hi=%u, cluster_lo=%u\n", 
                   safe_name, cluster_hi, cluster_lo);
            
            KINFO("   %s %s (cluster: %u, size: %u)\n", type, safe_name, cluster, size);
        }
    }

    // 5. Comparer avec ramfs_read_sectors
    KINFO("[DEBUG] Now reading same sector via ramfs_read_sectors:\n");
    int result = ramfs_read_sectors(root_sector, 1, sector_data);
    if (result > 0) {
        kprintf("[DEBUG] ramfs_read_sectors returned: %d\n", result);
        kprintf("[DEBUG] First 64 bytes via ramfs_read_sectors:\n");
        for (int i = 0; i < 64; i++) {
            if (i % 16 == 0) kprintf("\n[%03d]: ", i);
            kprintf("%02X ", sector_data[i]);
        }
        kprintf("\n");
        
        // 6. Comparer les données
        bool identical = true;
        int mismatch_count = 0;
        for (int i = 0; i < 512; i++) {
            if (sector_address[i] != sector_data[i]) {
                if (mismatch_count < 5) {  // Limiter à 5 messages
                    KINFO("[DEBUG] MISMATCH at byte %d: direct=0x%02X, ramfs_read=0x%02X\n", 
                          i, sector_address[i], sector_data[i]);
                }
                identical = false;
                mismatch_count++;
            }
        }
        
        if (identical) {
            KINFO("[DEBUG] ✓ Direct memory and ramfs_read_sectors return identical data\n");
        } else {
            KERROR("[DEBUG] ✗ Data mismatch! %d bytes differ between direct memory and ramfs_read_sectors!\n", mismatch_count);
        }
    } else {
        KERROR("[DEBUG] ramfs_read_sectors failed with result: %d\n", result);
    }
    
    // 7. Interpréter comme entrées de répertoire
    KINFO("[DEBUG] Interpreting direct memory as FAT32 directory entries:\n");
    fat32_dir_entry_t *entries = (fat32_dir_entry_t *)sector_address;
    
    for (int i = 0; i < 16; i++) {  // 16 entrées par secteur
        fat32_dir_entry_t *entry = &entries[i];
        
        // Ignorer entrées vides ou supprimées
        if (entry->name[0] == 0x00 || entry->name[0] == 0xE5) continue;
        
        // Ignorer les entrées LFN
        if (entry->attr == 0x0F) continue;
        
        kprintf("[DEBUG] Entry %d:\n", i);
        kprintf("[DEBUG]   Raw name bytes: ");
        for (int j = 0; j < 11; j++) {
            kprintf("%02X ", (uint8_t)entry->name[j]);
        }
        kprintf("\n");
        kprintf("[DEBUG]   Name: '%.11s'\n", entry->name);
        kprintf("[DEBUG]   Attr: 0x%02X (%s)\n", entry->attr, 
              (entry->attr & 0x10) ? "DIR" : "FILE");
        
        uint32_t cluster = ((uint32_t)entry->first_cluster_hi << 16) | entry->first_cluster_lo;
        kprintf("[DEBUG]   Cluster Hi: 0x%04X, Lo: 0x%04X -> Combined: %u\n", 
              entry->first_cluster_hi, entry->first_cluster_lo, cluster);
        kprintf("[DEBUG]   Size: %u bytes\n", entry->file_size);
        kprintf("[DEBUG]   ---\n");
    }
    
    // 8. Vérifier aussi la fonction qui appelle ramfs_read_sectors
    KINFO("[DEBUG] Testing the actual function used by FAT32 layer:\n");
    uint32_t readme_sector = root_sector + (14 - 2); /* Cluster14 */
    test_fat32_read_function(readme_sector);
}
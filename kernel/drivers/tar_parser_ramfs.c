/* tar_parser_ramfs.c - Parser TAR pour integration RAMFS FAT32 */

#include <kernel/tar_parser_ramfs.h>
#include <kernel/string.h>
#include <kernel/ramfs.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/fat32.h>



/* Types de fichiers TAR */
#define TAR_TYPE_FILE        '0'
#define TAR_TYPE_HARDLINK    '1'
#define TAR_TYPE_SYMLINK     '2'
#define TAR_TYPE_CHARDEV     '3'
#define TAR_TYPE_BLOCKDEV    '4'
#define TAR_TYPE_DIRECTORY   '5'
#define TAR_TYPE_FIFO        '6'

/* Signature du fichier binaire cree par qemu_loader_method.sh */
#define USERFS_MAGIC "USERFS01"
#define USERFS_MAGIC_SIZE 8

/* Variables globales pour le parser */
static uint32_t g_next_cluster = 3;      /* Prochain cluster libre (apres root=2) */
static uint32_t g_fat_entries[4096];     /* Table FAT en memoire */
static uint32_t g_fat_entry_count = 3;   /* Nombre d'entrees utilisees */

static void update_fat_tables(void);

static void sync_fat_to_ramfs(void)
{
    extern fat32_fs_t fat32_fs;
    
    uint32_t fat_sectors = 1009;
    uint32_t fat1_start = 32;
    uint32_t fat2_start = 32 + fat_sectors;
    
    KDEBUG("Syncing FAT table to ramfs...\n");
    
    /* Écrire FAT1 */
    if (!ramfs_write_sectors(fat1_start, fat_sectors, fat32_fs.fat_table)) {
        KERROR("Failed to sync FAT1 to ramfs\n");
        return;
    }
    
    /* Écrire FAT2 (backup) */
    if (!ramfs_write_sectors(fat2_start, fat_sectors, fat32_fs.fat_table)) {
        KERROR("Failed to sync FAT2 to ramfs\n");
        return;
    }
    
    KDEBUG("FAT synchronized successfully\n");
}


/* Fonctions utilitaires TAR */
static uint32_t parse_octal_string(const char* str, size_t len)
{
    uint32_t result = 0;
    for (size_t i = 0; i < len && str[i] && str[i] != ' '; i++) {
        if (str[i] >= '0' && str[i] <= '7') {
            result = result * 8 + (str[i] - '0');
        }
    }
    return result;
}

static bool validate_tar_header(const tar_header_t* header)
{
    /* Verifier la signature USTAR */
    if (strncmp(header->magic, "ustar", 5) != 0) {
        return false;
    }
    
    /* Verifier que ce n'est pas un header vide (fin d'archive) */
    if (header->name[0] == '\0') {
        return false;
    }
    
    return true;
}

static uint32_t calculate_tar_checksum(const tar_header_t* header)
{
    uint32_t sum = 0;
    const uint8_t* bytes = (const uint8_t*)header;
    
    /* Calculer la somme en traitant le champ checksum comme des espaces */
    for (int i = 0; i < 512; i++) {
        if (i >= 148 && i < 156) {  /* Champ checksum */
            sum += ' ';
        } else {
            sum += bytes[i];
        }
    }
    
    return sum;
}

static uint32_t allocate_cluster(void)
{
    uint32_t cluster = g_next_cluster++;
    
    /* Marquer comme fin de chaîne par défaut */
    extern fat32_fs_t fat32_fs;
    fat32_fs.fat_table[cluster] = 0x0FFFFFFF;
    
    //KDEBUG("Allocated single cluster %u\n", cluster);
    return cluster;
}

/* Gestion des clusters FAT32 */
static uint32_t allocate_cluster2(void)
{
    uint32_t cluster = g_next_cluster++;
    
    // CORRECTION: Synchroniser les indices
    uint32_t fat_index = cluster - 2;  // Les clusters commencent à 2, FAT à 0
    if (fat_index < 4096) {
        g_fat_entries[fat_index] = 0x0FFFFFFF; /* End of chain */
    }
    
    //KDEBUG("[DEBUG] Allocated cluster %u (FAT index %u)\n", cluster, fat_index);
    return cluster;

}



static uint32_t allocate_file_clusters(uint32_t file_size)
{
    if (file_size == 0) return 0;
    
    uint32_t clusters_needed = (file_size + 511) / 512;
    uint32_t first_cluster = g_next_cluster;
    
    //KDEBUG("Allocating %u clusters starting from %u for file size %u\n", 
    //       clusters_needed, first_cluster, file_size);
    
    /* Chaîner dans la table locale */
    for (uint32_t i = 0; i < clusters_needed; i++) {
        uint32_t current_cluster = first_cluster + i;
        uint32_t fat_index = current_cluster - 2;  /* Index dans g_fat_entries */
        
        if (fat_index >= 4096) {
            KERROR("FAT index %u out of bounds\n", fat_index);
            break;
        }
        
        if (i == clusters_needed - 1) {
            /* Dernier cluster */
            g_fat_entries[fat_index] = 0x0FFFFFFF;
            //KDEBUG("g_fat_entries[%u] = 0x0FFFFFFF (cluster %u end)\n", 
            //       fat_index, current_cluster);
        } else {
            /* Cluster suivant */
            uint32_t next_cluster = current_cluster + 1;
            g_fat_entries[fat_index] = next_cluster;
            //KDEBUG("g_fat_entries[%u] = %u (cluster %u -> %u)\n", 
            //       fat_index, next_cluster, current_cluster, next_cluster);
        }
        
        g_next_cluster++;
    }
    
    /* Mettre à jour le compteur */
    g_fat_entry_count = MAX(g_fat_entry_count, g_next_cluster - 2);
    
    return first_cluster;
}



static uint32_t allocate_file_clusters2(uint32_t file_size)
{
    if (file_size == 0) return 0;
    
    /* SOLUTION ULTRA SIMPLE */
    uint32_t clusters_needed = 1;  // Toujours au moins 1 cluster
    if (file_size > 512) {
        clusters_needed = (file_size + 512 - 1) / 512;  // Seulement si > 512
    }
    
    uint32_t first_cluster = allocate_cluster();
    //KDEBUG("[DEBUG] Allocated cluster %u for file size %u (%u clusters needed)\n", 
    //       first_cluster, file_size, clusters_needed);
    
    uint32_t current_cluster = first_cluster;
    
    /* Allouer les clusters supplémentaires */
    for (uint32_t i = 1; i < clusters_needed; i++) {
        uint32_t next_cluster = allocate_cluster();
        g_fat_entries[current_cluster - 2] = next_cluster;
        current_cluster = next_cluster;
    }
    
    return first_cluster;
}

/* ecriture des donnees dans les clusters */
static void write_file_data_to_clusters(uint32_t first_cluster, const uint8_t* data, uint32_t size)
{
    uint32_t current_cluster = first_cluster;
    uint32_t remaining_size = size;
    uint32_t offset = 0;
    
    while (remaining_size > 0 && current_cluster != 0) {
        /* Calculer le secteur du cluster */
        uint32_t data_start_sector = 32 + 2 * 1009;  /* Apres les secteurs reserves et FAT */
        uint32_t sector = data_start_sector + (current_cluster - 2);
        
        /* ecrire les donnees du cluster */
        uint32_t bytes_to_write = (remaining_size > 512) ? 512 : remaining_size;
        uint8_t sector_data[512];
        
        memset(sector_data, 0, 512);
        memcpy(sector_data, data + offset, bytes_to_write);
        
        ramfs_write_sectors(sector, 1, sector_data);
        
        offset += bytes_to_write;
        remaining_size -= bytes_to_write;
        
        /* Passer au cluster suivant */
        if (remaining_size > 0) {
            current_cluster = g_fat_entries[current_cluster - 2];
        } else {
            break;
        }
    }
}

static void update_fat_tables(void)
{
    KDEBUG("Writing complete FAT tables to ramfs...\n");
    
    uint32_t fat_sectors = 1009;
    uint8_t* complete_fat = kmalloc(fat_sectors * 512);
    if (!complete_fat) {
        KERROR("Failed to allocate complete FAT buffer\n");
        return;
    }
    
    memset(complete_fat, 0, fat_sectors * 512);
    uint32_t* fat_array = (uint32_t*)complete_fat;
    
    /* Entrées spéciales */
    fat_array[0] = 0x0FFFFFF8;  /* Media descriptor */
    fat_array[1] = 0x0FFFFFFF;  /* End of chain */
    fat_array[2] = 0x0FFFFFFF;  /* Root directory end */
    
    /* CORRECTION : Copier avec le bon indexage */
    KDEBUG("Copying FAT entries with correct indexing...\n");
    for (uint32_t i = 0; i < 4096; i++) {
        if (g_fat_entries[i] != 0) {
            uint32_t cluster_num = i + 2;  /* g_fat_entries[0] = cluster 2 */
            fat_array[cluster_num] = g_fat_entries[i];
            
            //KDEBUG("FAT[%u] = 0x%08X (from g_fat_entries[%u])\n", 
            //       cluster_num, g_fat_entries[i], i);
        }
    }
    
    /* Vérification spéciale pour hello */
    //KDEBUG("=== HELLO CHAIN VERIFICATION ===\n");
    //for (uint32_t cluster = 14; cluster <= 25; cluster++) {
    //    KDEBUG("FAT[%u] = 0x%08X\n", cluster, fat_array[cluster]);
    //}
    //KDEBUG("=== END VERIFICATION ===\n");
    
    /* Écrire les FATs */
    if (!ramfs_write_sectors(32, fat_sectors, complete_fat)) {
        KERROR("Failed to write FAT1\n");
        kfree(complete_fat);
        return;
    }
    
    if (!ramfs_write_sectors(32 + fat_sectors, fat_sectors, complete_fat)) {
        KERROR("Failed to write FAT2\n");
        kfree(complete_fat);
        return;
    }
    
    //KDEBUG("FAT tables written successfully\n");
    kfree(complete_fat);
}


/* Mise a jour des tables FAT */
static void update_fat_tables2(void)
{
    uint8_t fat_sector[512];
    
    /* Initialiser le premier secteur FAT */
    memset(fat_sector, 0, 512);
    *(uint32_t*)(fat_sector + 0) = 0x0FFFFFF8;  /* Media descriptor */
    *(uint32_t*)(fat_sector + 4) = 0x0FFFFFFF;  /* End of chain */
    *(uint32_t*)(fat_sector + 8) = 0x0FFFFFFF;  /* Root directory */
    
    /* Ajouter les entrees allouees */
    uint32_t fat_offset = 12;  /* Commencer apres les 3 premieres entrees */
    for (uint32_t i = 3; i < g_fat_entry_count && fat_offset < 512; i++) {
        *(uint32_t*)(fat_sector + fat_offset) = g_fat_entries[i - 2];
        fat_offset += 4;
    }
    
    /* ecrire FAT1 et FAT2 */
    ramfs_write_sectors(32, 1, fat_sector);
    ramfs_write_sectors(32 + 1009, 1, fat_sector);
}

/* Conversion de nom en format 8.3 FAT */
static void convert_name_to_fat83(const char* name, char* fat_name)
{
    memset(fat_name, ' ', 11);
    
    const char* dot = strrchr(name, '.');
    
    if (dot && dot != name) {
        /* Fichier avec extension */
        uint32_t base_len = dot - name;
        if (base_len > 8) base_len = 8;
        memcpy(fat_name, name, base_len);
        
        uint32_t ext_len = strlen(dot + 1);
        if (ext_len > 3) ext_len = 3;
        memcpy(fat_name + 8, dot + 1, ext_len);
    } else {
        /* Fichier sans extension ou repertoire */
        uint32_t name_len = strlen(name);
        if (name_len > 8) name_len = 8;
        memcpy(fat_name, name, name_len);
    }
    
    /* Convertir en majuscules */
    for (int i = 0; i < 11; i++) {
        if (fat_name[i] >= 'a' && fat_name[i] <= 'z') {
            fat_name[i] = fat_name[i] - 'a' + 'A';
        }
    }
}

/* ecriture d'une entree de repertoire FAT32 */
static void write_directory_entry(uint8_t* dir_data, uint32_t* offset,
                                const char* name, uint32_t first_cluster,
                                uint32_t size, uint8_t attr)
{
    if (*offset >= 512) return;

    //KDEBUG("[DEBUG] Creating directory entry: '%s' → cluster %u, size %u\n", 
    //      name, first_cluster, size);  // ← AJOUTEZ CECI
    
    uint8_t* entry = dir_data + *offset;
    char fat_name[11];
    
    convert_name_to_fat83(name, fat_name);
    
    memcpy(entry, fat_name, 11);
    entry[11] = attr;
    *(uint16_t*)(entry + 26) = first_cluster & 0xFFFF;        /* Cluster bas */
    *(uint16_t*)(entry + 20) = (first_cluster >> 16) & 0xFFFF; /* Cluster haut */
    *(uint32_t*)(entry + 28) = size;
    
    *offset += 32;
}

/* Creation d'un repertoire FAT32 */
static uint32_t create_fat_directory(tar_dir_entry_t* dir)
{
    if (!dir) return 0;
    
    /* Pour le repertoire racine, utiliser le cluster 2 fixe */
    if (strcmp(dir->name, "/") == 0) {
        dir->first_cluster = 2;
    } else {
        dir->first_cluster = allocate_cluster();
    }
    
    /* Calculer le secteur du repertoire */
    uint32_t data_start_sector = 32 + 2 * 1009;
    uint32_t sector = data_start_sector + (dir->first_cluster - 2);
    
    //KDEBUG("Creating directory '%s' at cluster %u (sector %u)\n", 
    //       dir->name, dir->first_cluster, sector);
    
    uint8_t dir_data[512];
    memset(dir_data, 0, 512);
    uint32_t entry_offset = 0;
    
    /* Compter les fichiers et sous-repertoires */
    uint32_t file_count = 0;
    uint32_t subdir_count = 0;
    
    tar_file_entry_t* file = dir->files;
    while (file) {
        file_count++;
        file = file->next;
    }
    
    tar_dir_entry_t* subdir = dir->subdirs;
    while (subdir) {
        subdir_count++;
        subdir = subdir->next;
    }
    
    //KDEBUG("Directory '%s': %u files, %u subdirs\n", 
    //       dir->name, file_count, subdir_count);
    
    /* ecrire les entrees de fichiers */
    file = dir->files;
    while (file && entry_offset < 480) {  /* Laisser de la place */
        //KDEBUG("Adding file '%s' to directory '%s'\n", file->name, dir->name);
        
        write_directory_entry(dir_data, &entry_offset, file->name,
                            file->first_cluster, file->size, file->attr);
        file = file->next;
    }
    
    /* ecrire les entrees de sous-repertoires */
    subdir = dir->subdirs;
    while (subdir && entry_offset < 480) {
        //KDEBUG("Adding subdir '%s' to directory '%s'\n", subdir->name, dir->name);
        
        write_directory_entry(dir_data, &entry_offset, subdir->name,
                            subdir->first_cluster, 0, 0x10);
        subdir = subdir->next;
    }
    
    /* ecrire le repertoire sur le disque */
    //KDEBUG("Writing directory '%s' to sector %u (%u bytes used)\n", 
    //       dir->name, sector, entry_offset);
    
    int result = ramfs_write_sectors(sector, 1, dir_data);
    if (result <= 0) {
        KERROR("Failed to write directory '%s' to sector %u\n", dir->name, sector);
        return 0;
    }
    
    //KDEBUG("OK Directory '%s' written successfully\n", dir->name);
    return dir->first_cluster;
}

/* Recherche ou creation d'un repertoire dans l'arbre */
static tar_dir_entry_t* find_or_create_directory(tar_dir_entry_t* root, const char* path)
{
    if (!path || path[0] == '\0') return root;
    
    char path_copy[512];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    
    char* token = strtok(path_copy, "/");
    tar_dir_entry_t* current = root;
    
    while (token) {
        /* Chercher le repertoire dans les sous-repertoires actuels */
        tar_dir_entry_t* found = NULL;
        tar_dir_entry_t* subdir = current->subdirs;
        
        while (subdir) {
            if (strcmp(subdir->name, token) == 0) {
                found = subdir;
                break;
            }
            subdir = subdir->next;
        }
        
        if (!found) {
            /* Creer le nouveau repertoire */
            found = kmalloc(sizeof(tar_dir_entry_t));
            memset(found, 0, sizeof(tar_dir_entry_t));
            strncpy(found->name, token, sizeof(found->name) - 1);
            found->parent = current;
            
            /* Ajouter a la liste des sous-repertoires */
            found->next = current->subdirs;
            current->subdirs = found;
        }
        
        current = found;
        token = strtok(NULL, "/");
    }
    
    return current;
}

void fix_root_in_tar_parser(int root_cluster)
{
    KINFO("Fixing root directory structure in TAR parser...\n");
    
    /* Le probleme : le root directory (cluster 2) pointe vers "." (cluster 33)
     * Solution : copier le contenu du cluster 33 vers le cluster 2 */
    
    uint32_t data_start_sector = 32 + 2 * 1009;
    uint32_t root_sector = data_start_sector;  /* Cluster 2 */
    uint32_t main_sector = data_start_sector + (root_cluster - 2);  /* Cluster 33 */
    //uint32_t main_sector = data_start_sector + (33 - 2);  /* Cluster 33 */

   
    /* Lire le repertoire principal */
    uint8_t main_dir_data[512];
    int result = ramfs_read_sectors(main_sector, 1, main_dir_data);
    
    if (result > 0) {
        /* Copier vers le root */
        result = ramfs_write_sectors(root_sector, 1, main_dir_data);
        
        if (result > 0) {
            KINFO("OK Root directory structure fixed - all files now in root\n");
        } else {
            KERROR("KO Failed to write fixed root directory\n");
        }
    } else {
        KERROR("KO Failed to read main directory for fix\n");
    }
}


/* Parser principal du fichier TAR */
int parse_tar_to_ramfs(const uint8_t* buffer, uint32_t buffer_size)
{
    //KINFO("Parsing TAR file to RAMFS FAT32...\n");
    
    /* Verifier la signature du fichier binaire */
    if (buffer_size < USERFS_MAGIC_SIZE + 4) {
        KERROR("Buffer too small for USERFS format\n");
        return -1;
    }
    
    if (memcmp(buffer, USERFS_MAGIC, USERFS_MAGIC_SIZE) != 0) {
        KERROR("Invalid USERFS magic signature\n");
        return -1;
    }
    
    /* Lire la taille du TAR */
    uint32_t tar_size = *(uint32_t*)(buffer + USERFS_MAGIC_SIZE);
    if (tar_size + USERFS_MAGIC_SIZE + 4 > buffer_size) {
        KERROR("TAR size mismatch\n");
        return -1;
    }
    
    /* Pointer vers les donnees TAR */
    const uint8_t* tar_data = buffer + USERFS_MAGIC_SIZE + 4;
    
    /* Initialiser le repertoire racine */
    tar_dir_entry_t root = {0};
    strncpy(root.name, "/", sizeof(root.name) - 1);
    root.first_cluster = 2;  /* Cluster racine FAT32 */
    
    /* Parser les entrees TAR */
    uint32_t offset = 0;
    uint32_t files_created = 0;
    uint32_t dirs_created = 0;

    static uint32_t root_cluster = 2;
    
    while (offset + sizeof(tar_header_t) <= tar_size) {
        const tar_header_t* header = (const tar_header_t*)(tar_data + offset);
        
        /* Verifier si c'est la fin de l'archive */
        if (!validate_tar_header(header)) {
            break;
        }
        
        /* Parser les informations du fichier */
        uint32_t file_size = parse_octal_string(header->size, 12);
        char full_path[256];
        
        /* Construire le chemin complet */
        if (header->prefix[0] != '\0') {
            snprintf(full_path, sizeof(full_path), "%.*s/%.*s", 
                    (int)sizeof(header->prefix), header->prefix,
                    (int)sizeof(header->name), header->name);
        } else {
            strncpy(full_path, header->name, sizeof(full_path) - 1);
            full_path[sizeof(full_path) - 1] = '\0';
        }
        
        //KDEBUG("Processing: %s (type=%c, size=%u)\n", full_path, header->typeflag, file_size);
        
        if (header->typeflag == TAR_TYPE_DIRECTORY || header->typeflag == '5') {
            /* Creer le repertoire */
            char dir_path[256];
            strncpy(dir_path, full_path, sizeof(dir_path) - 1);
            dir_path[sizeof(dir_path) - 1] = '\0';
            
            /* Enlever le slash final s'il existe */
            size_t len = strlen(dir_path);
            if (len > 0 && dir_path[len - 1] == '/') {
                dir_path[len - 1] = '\0';
            }
            
            find_or_create_directory(&root, dir_path);
            dirs_created++;
            
        } else if (header->typeflag == TAR_TYPE_FILE || header->typeflag == '\0') {
            /* Traiter le fichier */
            
            /* Separer le chemin et le nom du fichier */
            char* last_slash = strrchr(full_path, '/');
            char* filename;
            char dir_path[256] = {0};
            
            if (last_slash) {
                *last_slash = '\0';
                filename = last_slash + 1;
                strncpy(dir_path, full_path, sizeof(dir_path) - 1);
            } else {
                filename = full_path;
            }
            
            /* Trouver ou creer le repertoire parent */
            tar_dir_entry_t* parent_dir = find_or_create_directory(&root, dir_path);
            
            /* Creer l'entree de fichier */
            tar_file_entry_t* file_entry = kmalloc(sizeof(tar_file_entry_t));
            memset(file_entry, 0, sizeof(tar_file_entry_t));
            
            strncpy(file_entry->name, filename, sizeof(file_entry->name) - 1);
            file_entry->size = file_size;
            file_entry->attr = 0x20;  /* Archive attribute */
            
            /* Allouer les clusters et copier les donnees */
            if (file_size > 0) {
                file_entry->first_cluster = allocate_file_clusters(file_size);
                
                /* Copier les donnees du fichier */
                uint32_t data_offset = offset + sizeof(tar_header_t);
                if (data_offset + file_size <= tar_size) {
                    write_file_data_to_clusters(file_entry->first_cluster,
                                              tar_data + data_offset, file_size);
                }
            }
            
            /* Ajouter a la liste des fichiers du repertoire */
            file_entry->next = parent_dir->files;
            parent_dir->files = file_entry;
            
            files_created++;
        }
        
        /* Passer a la prochaine entree (les donnees sont alignees sur 512 bytes) */
        offset += sizeof(tar_header_t);
        if (file_size > 0) {
            offset += ((file_size + 511) / 512) * 512;  /* Arrondir a 512 */
        }
    }
    
    /* Creer recursivement tous les repertoires dans le systeme FAT32 */
    void create_directories_recursive(tar_dir_entry_t* dir) {
        if (!dir) return;
        
        //KDEBUG("Processing directory: '%s'\n", dir->name);
        
        /* Creer d'abord les sous-repertoires */
        tar_dir_entry_t* subdir = dir->subdirs;
        while (subdir) {
            create_directories_recursive(subdir);
            subdir = subdir->next;
        }
        
        /* Puis creer ce repertoire */
        uint32_t cluster = create_fat_directory(dir);
        if (cluster > 0) {
            //KDEBUG("OK Directory '%s' created at cluster %u\n", dir->name, cluster);
            if(strcmp(dir->name,".") == 0)
                root_cluster = cluster;
        } else {
            KERROR("KO Failed to create directory '%s'\n", dir->name);
        }
    }
    
    create_directories_recursive(&root);
    
    /* Creer le repertoire racine */
    create_fat_directory(&root);
    
    /* Mettre a jour les tables FAT */
    update_fat_tables();
    
    KINFO("OK TAR parsing complete: %u files, %u directories created\n", 
          files_created, dirs_created);
    
    /* Liberer la memoire (optionnel selon votre gestionnaire de memoire) */
    void free_directory_tree(tar_dir_entry_t* dir) {
        tar_file_entry_t* file = dir->files;
        while (file) {
            tar_file_entry_t* next = file->next;
            kfree(file);
            file = next;
        }
        
        tar_dir_entry_t* subdir = dir->subdirs;
        while (subdir) {
            tar_dir_entry_t* next = subdir->next;
            free_directory_tree(subdir);
            kfree(subdir);
            subdir = next;
        }
    }
    
    free_directory_tree(&root);

    fix_root_in_tar_parser(root_cluster);
    
    return 0;
}

/* Fonction d'initialisation complete du systeme de fichiers */
int load_userfs_from_memory(const uint8_t* buffer, uint32_t buffer_size) 
{
    KINFO("Loading USERFS from memory buffer...\n");
    
    /* Initialiser le systeme FAT32 de base */
    create_fat32_boot_sector();
    create_fat32_fat_tables();
    create_fat32_root_directory();

    //extern ramfs_device_t ramfs_device;

    //uint8_t* original_base = ramfs_device.memory_base;
    //ramfs_device.memory_base = destination;

    /* Parser et integrer le contenu TAR */
    int result = parse_tar_to_ramfs(buffer, buffer_size);

        // Restaurer
    //ramfs_device.memory_base = original_base;
    
    if (result == 0) {
        KINFO("OK USERFS loaded successfully into RAMFS FAT32\n");
    } else {
        KERROR("KO Failed to load USERFS\n");
    }
    
    return result;
} 
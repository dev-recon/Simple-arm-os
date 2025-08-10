#include <kernel/vfs.h>
#include <kernel/fat32.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

/* Forward declarations */
static inode_t* fat32_inode_lookup(inode_t* dir, const char* name);
static ssize_t fat32_file_read(file_t* file, void* buffer, size_t count);
static int fat32_file_open(inode_t* inode, file_t* file);
static int fat32_file_close(file_t* file);
static off_t fat32_file_lseek(file_t* file, off_t offset, int whence);
static int fat32_dir_readdir(file_t* file, dirent_t* dirent);

/* Operations tables */
file_operations_t fat32_file_ops = {
    .read = fat32_file_read,
    .write = NULL, /* Read-only for now */
    .open = fat32_file_open,
    .close = fat32_file_close,
    .lseek = fat32_file_lseek,
    .readdir = NULL
};

file_operations_t fat32_dir_ops = {
    .read = NULL,
    .write = NULL,
    .open = fat32_file_open,
    .close = fat32_file_close,
    .lseek = NULL,
    .readdir = fat32_dir_readdir
};

inode_operations_t fat32_inode_ops = {
    .lookup = fat32_inode_lookup,
    .create = NULL,
    .mkdir = NULL,
    .unlink = NULL
};

static inode_t* fat32_inode_lookup(inode_t* dir, const char* name)
{
    fat32_dir_entry_t* entry;
    inode_t* inode;
    uint32_t first_cluster;
    
    if (!S_ISDIR(dir->mode)) return NULL;
    
    entry = fat32_find_file(dir->first_cluster, name);
    if (!entry) return NULL;
    
    /* Create inode for this file */
    inode = create_inode();
    if (!inode) {
        kfree(entry);
        return NULL;
    }
    
    /* Fill inode from FAT32 entry */
    first_cluster = (entry->first_cluster_hi << 16) | entry->first_cluster_lo;
    
    inode->mode = (entry->attr & FAT_ATTR_DIRECTORY) ? S_IFDIR : S_IFREG;
    inode->mode |= 0755; /* rwxrw-rw- */
    inode->uid = 0;
    inode->gid = 0;
    inode->size = entry->file_size;
    inode->first_cluster = first_cluster;
    inode->parent_cluster = dir->first_cluster;
    
    /* Convert FAT32 dates */
    inode->mtime = fat32_date_to_unix(entry->write_date, entry->write_time);
    inode->atime = inode->mtime;
    inode->ctime = inode->mtime;
    
    /* Assign operations */
    if (S_ISDIR(inode->mode)) {
        inode->i_op = &fat32_inode_ops;
        inode->f_op = &fat32_dir_ops;
    } else {
        inode->i_op = &fat32_inode_ops;
        inode->f_op = &fat32_file_ops;
    }
    
    kfree(entry);
    return inode;
}

static ssize_t fat32_file_read(file_t* file, void* buffer, size_t count)
{
    inode_t* inode = file->inode;
    void* file_buffer;
    int bytes_read;
    
    /* Check bounds */
    if (file->offset >= inode->size) {
        return 0; /* EOF */
    }

    //KDEBUG("fat32_file_read : reading at offset %d for inode of size %d\n", file->offset, inode->size);
    
    if (file->offset + count > inode->size) {
        count = inode->size - file->offset;
    }
    
    /* Allocate buffer for entire file (simple approach) */
    file_buffer = kmalloc(inode->size);
    if (!file_buffer) return -ENOMEM;
    
    /* Read entire file */
    bytes_read = fat32_read_file(inode->first_cluster, inode->size, file_buffer);
    if (bytes_read < 0) {
        kfree(file_buffer);
        return bytes_read;
    }
    
    /* Copy requested portion */
    memcpy(buffer, (char*)file_buffer + file->offset, count);
    file->offset += count;

    /*KDEBUG("fat32_file_read : succefully red %d bytes - count %d\n", bytes_read, count);
    KINFO("[fat32_file_read] read function succeeded\n");
    KINFO("[fat32_file_read] First 512 bytes:\n");
    for (int i = 0; i < (int)inode->size; i++) {
        if (i % 48 == 0) kprintf("\n[%03d]: ", i);
        kprintf("%02X ", *(char *)(file_buffer+i));
    }
    kprintf("\n");*/
    
    kfree(file_buffer);
    return count;
}

static int fat32_file_open(inode_t* inode, file_t* file)
{
    /* Basic validation */
    if (S_ISDIR(inode->mode) && (file->flags & (O_WRONLY | O_RDWR))) {
        return -EISDIR;
    }
    
    if ((file->flags & (O_WRONLY | O_RDWR))) {
        return -EROFS; /* Read-only filesystem */
    }
    
    return 0;
}

static int fat32_file_close(file_t* file)
{
    /* Suppress unused parameter warning */
    (void)file;
    
    /* Nothing special to do for FAT32 */
    return 0;
}

static off_t fat32_file_lseek(file_t* file, off_t offset, int whence)
{
    inode_t* inode = file->inode;
    off_t new_offset;
    
    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = file->offset + offset;
            break;
        case SEEK_END:
            new_offset = inode->size + offset;
            break;
        default:
            return -EINVAL;
    }
    
    if (new_offset < 0) return -EINVAL;
    
    file->offset = new_offset;
    return new_offset;
}

static int fat32_dir_readdir(file_t* file, dirent_t* dirent)
{
    inode_t* dir_inode = file->inode;
    uint32_t cluster = dir_inode->first_cluster;
    uint32_t target_entry = file->offset;
    uint32_t entry_count = 0;
    
    if (!S_ISDIR(dir_inode->mode)) {
        KDEBUG("[READDIR] Not a directory (mode: 0x%04X)\n", dir_inode->mode);
        return -ENOTDIR;
    }
    
    // KDEBUG("[READDIR] Reading directory cluster %u, target entry %u\n", 
    //       cluster, target_entry);
    
    /* Parcourir les clusters du repertoire */
    while (cluster && cluster >= 2 && cluster < 0x0FFFFFF8) {
        uint32_t bytes_per_cluster = get_fat32_bytes_per_cluster();
        void* cluster_buf = kmalloc(bytes_per_cluster);
        if (!cluster_buf) {
            KERROR("[READDIR] Failed to allocate cluster buffer\n");
            return -ENOMEM;
        }
        
        /* Lire le cluster */
        if (fat32_read_cluster(cluster, cluster_buf) < 0) {
            KERROR("[READDIR] Failed to read cluster %u\n", cluster);
            kfree(cluster_buf);
            return -EIO;
        }
        
        fat32_dir_entry_t* entries = (fat32_dir_entry_t*)cluster_buf;
        uint32_t entries_per_cluster = bytes_per_cluster / sizeof(fat32_dir_entry_t);
        
        //KDEBUG("[READDIR] Cluster %u: %u entries to check\n", cluster, entries_per_cluster);
        
        /* Parcourir les entrees du cluster */
        for (uint32_t i = 0; i < entries_per_cluster; i++) {
            fat32_dir_entry_t* entry = &entries[i];
            
            /* Fin du repertoire */
            if (entry->name[0] == 0) {
                //KDEBUG("[READDIR] End of directory reached\n");
                kfree(cluster_buf);
                return 0;
            }
            
            /* Ignorer les entrees supprimees et LFN */
            if (entry->name[0] == 0xE5 || entry->attr == FAT_ATTR_LFN) {
                continue;
            }
            
            /* Si c'est l'entree cible */
            if (entry_count == target_entry) {
                /* Remplir la structure dirent */
                dirent->d_ino = (entry->first_cluster_hi << 16) | entry->first_cluster_lo;
                dirent->d_type = (entry->attr & FAT_ATTR_DIRECTORY) ? DT_DIR : DT_REG;
                
                /* Convertir le nom 8.3 */
                fat32_83_to_name((char*)entry->name, dirent->d_name);
                dirent->d_reclen = sizeof(dirent_t);
                
                //KDEBUG("[READDIR] Found entry %u: '%s' (type: %s, cluster: %u)\n",
                //       entry_count, dirent->d_name,
                //       (dirent->d_type == DT_DIR) ? "DIR" : "FILE",
                //       (uint32_t)dirent->d_ino);
                
                /* Incrementer l'offset pour la prochaine lecture */
                file->offset++;
                
                kfree(cluster_buf);
                return 1; /* Succes */
            }
            
            entry_count++;
        }
        
        kfree(cluster_buf);
        
        /* Passer au cluster suivant */
        cluster = get_next_cluster(cluster);
        KDEBUG("[READDIR] Moving to next cluster: %u\n", cluster);
    }
    
    KDEBUG("[READDIR] No more entries found\n");
    return 0; /* Fin du repertoire */
}

static int fat32_dir_readdir2(file_t* file, dirent_t* dirent)
{
    inode_t* dir_inode = file->inode;
    uint32_t cluster;
    uint32_t entry_count = 0;
    uint32_t target_entry;
    void* cluster_buf;
    fat32_dir_entry_t* entries;
    uint32_t entries_per_cluster;
    uint32_t i;
    fat32_dir_entry_t* entry;
    uint32_t bytes_per_cluster;
    
    if (!S_ISDIR(dir_inode->mode)) return -ENOTDIR;

    KDEBUG("[DIR] fat32_dir_readdir \n");
    
    cluster = dir_inode->first_cluster;
    target_entry = file->offset;
    bytes_per_cluster = get_fat32_bytes_per_cluster();

    KDEBUG("[DIR] cluster = %u, target_entry = %u, bytes_per_cluster = %u\n", cluster, target_entry, bytes_per_cluster);

    
    while (cluster && cluster < 0x0FFFFFF8) {
        cluster_buf = kmalloc(bytes_per_cluster);
        if (!cluster_buf) return -ENOMEM;
        
        if (fat32_read_cluster(cluster, cluster_buf) < 0) {
            kfree(cluster_buf);
            return -EIO;
        }
        
        entries = (fat32_dir_entry_t*)cluster_buf;
        entries_per_cluster = bytes_per_cluster / sizeof(fat32_dir_entry_t);

        KDEBUG("[DIR] entries = %u, entries_per_cluster = %u \n", entries, entries_per_cluster);

        
        for (i = 0; i < entries_per_cluster; i++) {
            entry = &entries[i];
            
            /* End of directory */
            if (entry->name[0] == 0) {
                kfree(cluster_buf);
                return 0;
            }
            
            /* Skip deleted and LFN entries */
            if (entry->name[0] == 0xE5 || entry->attr == FAT_ATTR_LFN) {
                continue;
            }
            
            /* If this is the target entry */
            if (entry_count == target_entry) {
                dirent->d_ino = 0; /* TODO: compute inode number */
                dirent->d_type = (entry->attr & FAT_ATTR_DIRECTORY) ? DT_DIR : DT_REG;
                
                /* Convert name */
                fat32_83_to_name(entry->name, dirent->d_name);
                dirent->d_reclen = sizeof(dirent_t) + strlen(dirent->d_name) + 1;
                
                file->offset++;
                kfree(cluster_buf);
                return 1;
            }
            
            entry_count++;
        }
        
        kfree(cluster_buf);
        cluster = get_next_cluster(cluster);
    }
    
    return 0; /* End of directory */
}
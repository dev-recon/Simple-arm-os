/* kernel/fs/vfs.c */
#include <kernel/vfs.h>
#include <kernel/fat32.h>
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#include <kernel/task.h>

#define MAX_INODES 1024

static inode_t* inode_table[MAX_INODES] = {0};
static inode_t* root_inode = NULL;
static uint32_t next_inode_number = 1;
static spinlock_t vfs_lock;

/* File operations for FAT32 */
extern file_operations_t fat32_file_ops;
extern file_operations_t fat32_dir_ops;
extern inode_operations_t fat32_inode_ops;



/*void test_root_directory(void) {
    if (!root_inode || !root_inode->f_op || !root_inode->f_op->readdir) {
        KERROR("[TEST] Root directory not readable\n");
        return;
    }
    
    // Essayer de lire le contenu du répertoire racine
    struct dirent entries[25];
    int count = root_inode->f_op->readdir(root_inode, entries);
    
    KINFO("[TEST] Root directory contains %d entries:\n", count);
    for (int i = 0; i < count; i++) {
        KINFO("[TEST]   - %s (type: %d)\n", entries[i].d_name, entries[i].d_type);
    }
}*/

uint32_t get_next_inode_number(void){
    return next_inode_number++; 
}

bool init_vfs(void)
{
    KINFO("[VFS] Starting VFS initialization...\n");
    
    init_spinlock(&vfs_lock);
    
    /* Initialiser FAT32 d'abord */
    if (init_fat32() != 0) {
        KERROR("[VFS] Failed to initialize FAT32\n");
        return false;
    }
    
    /* Monter le systeme de fichiers */
    if (mount_fat32_filesystem() != 0) {
        KERROR("[VFS] Failed to mount FAT32\n");
        return false;
    }
    
    /* Creer l'inode racine */
    root_inode = create_inode();
    if (!root_inode) {
        KERROR("[VFS] Failed to create root inode\n");
        return false;
    }
    
    /* CORRECTION: Configuration correcte de l'inode racine */
    root_inode->ino = 1;
    root_inode->mode = S_IFDIR | 0755;
    root_inode->uid = 0;
    root_inode->gid = 0;
    root_inode->size = 0;
    root_inode->first_cluster = get_fat32_root_cluster();
    root_inode->i_op = &fat32_inode_ops;
    root_inode->f_op = &fat32_dir_ops;
    
    /* Timestamps */
    root_inode->atime = 0;
    root_inode->mtime = 0;
    root_inode->ctime = 0;
    
    KINFO("[VFS] Root inode created:\n");
    KINFO("[VFS]   Inode number: %u\n", root_inode->ino);
    KINFO("[VFS]   Mode: 0x%04X (%s)\n", root_inode->mode,
          S_ISDIR(root_inode->mode) ? "directory" : "other");
    KINFO("[VFS]   First cluster: %u\n", root_inode->first_cluster);
    KINFO("[VFS]   Operations: i_op=%p, f_op=%p\n", root_inode->i_op, root_inode->f_op);
    
    /* Test de l'inode racine */
    if (root_inode->f_op && root_inode->f_op->readdir) {
        KINFO("[VFS] OK Root inode has readdir operation\n");
    } else {
        KERROR("[VFS] KO Root inode missing readdir operation\n");
    }

    //test_root_directory();
    
    KINFO("[VFS] OK VFS initialized successfully\n");
    return true;
}

bool init_vfs2(void)
{
    KDEBUG("Starting init_vfs ....\n");
    init_spinlock(&vfs_lock);
    KDEBUG("init_spinlock Ok ....\n");

    /* Mount FAT32 */
    if (!fat32_mount()) {
        KERROR("VFS: Failed to mount FAT32\n");
        return false;
    }

    KDEBUG("fat32_mount Ok ....\n");

    /* Create root inode */
    root_inode = create_inode();
    if (!root_inode) {
        return false;
    }
    
    KDEBUG("create_inode Ok ....\n");

    root_inode->ino = 1;
    root_inode->mode = S_IFDIR | 0755;
    root_inode->uid = 0;
    root_inode->gid = 0;
    root_inode->size = 0;
    root_inode->first_cluster = get_fat32_root_cluster();
    root_inode->i_op = &fat32_inode_ops;
    root_inode->f_op = &fat32_dir_ops;
    
    KDEBUG("VFS: Initialized\n");
    return true;
}

inode_t* create_inode(void)
{
    inode_t* inode;
    uint32_t hash;
    
    inode = (inode_t*)kmalloc(sizeof(inode_t));
    if (!inode) return NULL;
    
    memset(inode, 0, sizeof(inode_t));
    
    spin_lock(&vfs_lock);
    inode->ino = get_next_inode_number();
    spin_unlock(&vfs_lock);
    
    inode->ref_count = 1;
    
    /* Add to hash table */
    hash = inode->ino % MAX_INODES;
    spin_lock(&vfs_lock);
    inode->next = inode_table[hash];
    inode_table[hash] = inode;
    spin_unlock(&vfs_lock);
    
    return inode;
}

inode_t* get_inode(uint32_t ino)
{
    uint32_t hash;
    inode_t* inode;
    
    hash = ino % MAX_INODES;
    
    spin_lock(&vfs_lock);
    inode = inode_table[hash];
    
    while (inode) {
        if (inode->ino == ino) {
            inode->ref_count++;
            spin_unlock(&vfs_lock);
            return inode;
        }
        inode = inode->next;
    }
    spin_unlock(&vfs_lock);
    
    return NULL;
}

void put_inode(inode_t* inode)
{
    uint32_t hash;
    inode_t** current;
    
    if (!inode) return;
    
    spin_lock(&vfs_lock);
    inode->ref_count--;
    
    if (inode->ref_count == 0) {
        /* Remove from hash table */
        hash = inode->ino % MAX_INODES;
        current = &inode_table[hash];
        
        while (*current) {
            if (*current == inode) {
                *current = inode->next;
                break;
            }
            current = &(*current)->next;
        }
        
        spin_unlock(&vfs_lock);
        kfree(inode);
    } else {
        spin_unlock(&vfs_lock);
    }
}

inode_t* path_lookup(const char* path)
{
    inode_t* current;
    char* path_copy;
    char* token;
    
    if (!path || path[0] != '/') {
        return NULL;
    }
    
    current = root_inode;
    current->ref_count++;
    
    if (strcmp(path, "/") == 0) {
        return current;
    }
    
    /* Copy path for tokenization */
    path_copy = strdup(path);
    if (!path_copy) {
        put_inode(current);
        return NULL;
    }
    
    /* Use standard strtok function */
    token = strtok(path_copy + 1, "/");
    
    while (token && current) {
        inode_t* next;
        
        if (!S_ISDIR(current->mode)) {
            put_inode(current);
            current = NULL;
            break;
        }
        
        next = current->i_op->lookup(current, token);
        put_inode(current);
        current = next;
        
        token = strtok(NULL, "/");
    }
    
    kfree(path_copy);
    return current;
}

/**
 * Allouer un descripteur de fichier - CORRIGe
 */
int allocate_fd(task_t* process)
{
    int i;
    
    if (!process || process->type != TASK_TYPE_PROCESS) {
        KERROR("NULL PROC\n");
        return -EINVAL;
    }
    
    /* ACCeS CORRECT */
    for (i = 0; i < MAX_FILES; i++) {
        if (process->process->files[i] == NULL) {
            return i;
        }
    }
    
    return -EMFILE;
}


void free_fd(task_t* proc, int fd)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("NULL PROC\n");
        return ;
    }
 
    if (fd >= 0 && fd < MAX_FILES) {
        proc->process->files[fd] = NULL;
    }
}

inode_t* get_root_inode(void)
{
    if (root_inode) {
        root_inode->ref_count++;
        return root_inode;
    }
    return NULL;
}

void close_cloexec_files(task_t* proc)
{
    int i;

    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("NULL PROC\n");
        return ;
    }

    
    for (i = 0; i < MAX_FILES; i++) {
        if (proc->process->files[i] && (proc->process->files[i]->flags & O_CLOEXEC)) {
            close_file(proc->process->files[i]);
            proc->process->files[i] = NULL;
        }
    }
}



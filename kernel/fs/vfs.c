/* kernel/fs/vfs.c */
#include <kernel/vfs.h>
#include <kernel/fat32.h>
#include <kernel/ext2.h>
#include <kernel/disk_layout.h>
#include <kernel/mount.h>
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

/* Mount table */
#define MAX_MOUNTS 8
typedef struct {
    char     path[128];
    inode_t* root;
} mount_entry_t;
static mount_entry_t mount_table[MAX_MOUNTS];
static int mount_count = 0;

int vfs_mount(const char* path, inode_t* root)
{
    if (!path || !root || mount_count >= MAX_MOUNTS) return -1;
    strncpy(mount_table[mount_count].path, path, 127);
    mount_table[mount_count].path[127] = '\0';
    mount_table[mount_count].root = root;
    mount_count++;
    KINFO("[VFS] Mounted '%s'\n", path);
    return 0;
}

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
    const disk_partition_t* ext2_part;
    const disk_partition_t* fat32_part;
    int fstab_mounts;

    KINFO("[VFS] Starting VFS initialization...\n");
    
    init_spinlock(&vfs_lock);

    ext2_part = disk_partition_get(DISK_PART_EXT2_ROOT);
    fat32_part = disk_partition_get(DISK_PART_FAT32_MNT);
    if (!ext2_part || !fat32_part) {
        KERROR("[VFS] Disk layout is invalid\n");
        return false;
    }

    /* Monter ext2 comme racine depuis le debut du disk.img. */
    KINFO("[VFS] Mounting %s (%s) at LBA %u\n",
          ext2_part->name, ext2_part->mountpoint, (uint32_t)ext2_part->lba_start);
    inode_t* ext2_root = ext2_mount(ext2_part->lba_start);
    if (!ext2_root) {
        KERROR("[VFS] ext2 not found on %s — root unavailable\n", ext2_part->name);
        return false;
    }

    root_inode = ext2_root;

    KINFO("[VFS] Root inode created from ext2:\n");
    KINFO("[VFS]   Inode number: %u\n", root_inode->ino);
    KINFO("[VFS]   Mode: 0x%04X (%s)\n", root_inode->mode,
          S_ISDIR(root_inode->mode) ? "directory" : "other");
    KINFO("[VFS]   First cluster/inode: %u\n", root_inode->first_cluster);
    KINFO("[VFS]   Operations: i_op=%p, f_op=%p\n", root_inode->i_op, root_inode->f_op);

    if (root_inode->f_op && root_inode->f_op->readdir) {
        KINFO("[VFS] OK ext2 root inode has readdir operation\n");
    } else {
        KERROR("[VFS] KO ext2 root inode missing readdir operation\n");
        return false;
    }

    //test_root_directory();

    fstab_mounts = vfs_mount_from_fstab(FSTAB_PATH);
    if (fstab_mounts <= 0) {
        KINFO("[VFS] Mounting static fallback for %s\n", fat32_part->mountpoint);
        if (vfs_mount_fat32_partition(fat32_part) != 0) {
            KERROR("[VFS] FAT32 fallback mount failed\n");
            return false;
        }
    }

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
    char*    path_copy;
    char*    token;
    char     current_path[256];

    if (!path || path[0] != '/') return NULL;

    current = root_inode;
    current->ref_count++;

    if (strcmp(path, "/") == 0) return current;

    path_copy = strdup(path);
    if (!path_copy) { put_inode(current); return NULL; }

    current_path[0] = '\0';
    token = strtok(path_copy + 1, "/");

    while (token && current) {
        if (!S_ISDIR(current->mode)) {
            put_inode(current);
            current = NULL;
            break;
        }

        inode_t* next = current->i_op->lookup(current, token);
        put_inode(current);
        current = next;

        if (current) {
            /* Build accumulated path and check for mount points */
            int plen = strlen(current_path);
            snprintf(current_path + plen, (int)sizeof(current_path) - plen,
                     "/%s", token);

            for (int i = 0; i < mount_count; i++) {
                if (strcmp(current_path, mount_table[i].path) == 0) {
                    put_inode(current);
                    current = mount_table[i].root;
                    current->ref_count++;
                    break;
                }
            }
        }

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

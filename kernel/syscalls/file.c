/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/syscalls/file.c
 * Layer: Kernel / syscall implementation
 *
 * Responsibilities:
 * - Validate user-facing syscall requests.
 * - Bridge user ABI arguments to kernel subsystems.
 *
 * Notes:
 * - Never trust user pointers; copy through checked helpers.
 */

#include <kernel/task.h>
#include <kernel/syscalls.h>
#include <kernel/vfs.h>
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/userspace.h>
#include <kernel/kprintf.h>
#include <kernel/fat32.h>
#include <kernel/ext2.h>
#include <kernel/timer.h>
#include <kernel/dirent.h>
#include <kernel/tty.h>
#include <kernel/null.h>
#include <kernel/virtio_net.h>
#include <kernel/spinlock.h>
#include <asm/mmu.h>


/* Forward declarations de toutes les fonctions statiques */
static bool check_file_permission(inode_t* inode, int flags);
extern int fat32_file_exists_in_dir(inode_t* dir_inode, const char* filename);
extern inode_t* fat32_create_file(const char* parent_path, const char* filename, mode_t mode);
extern void fat32_free_cluster_chain(uint32_t start_cluster);
extern int fat32_update_file_by_name(const char* filename, uint32_t parent_cluster, uint32_t new_cluster);
extern int fat32_update_file_size_in_dir(const char* filename, uint32_t parent_cluster, uint32_t new_size);
extern file_operations_t fat32_file_ops;
extern inode_operations_t fat32_inode_ops;
extern file_operations_t ext2_file_ops;
extern inode_operations_t ext2_inode_ops;

static spinlock_t file_ref_lock = SPINLOCK_INIT("file_ref");

bool inode_permission(inode_t* inode, int mask) {
    /* Root peut tout faire */
    if (current_uid() == 0) return true;
    
    /* Propriétaire du fichier */
    if (current_uid() == inode->uid) {
        if ((mask & MAY_READ) && !(inode->mode & 0400)) return false;
        if ((mask & MAY_WRITE) && !(inode->mode & 0200)) return false;
        if ((mask & MAY_EXEC) && !(inode->mode & 0100)) return false;
        return true;
    }
    
    /* Groupe du fichier */
    if (current_gid() == inode->gid) {
        if ((mask & MAY_READ) && !(inode->mode & 0040)) return false;
        if ((mask & MAY_WRITE) && !(inode->mode & 0020)) return false;
        if ((mask & MAY_EXEC) && !(inode->mode & 0010)) return false;
        return true;
    }
    
    /* Autres utilisateurs */
    if ((mask & MAY_READ) && !(inode->mode & 0004)) return false;
    if ((mask & MAY_WRITE) && !(inode->mode & 0002)) return false;
    if ((mask & MAY_EXEC) && !(inode->mode & 0001)) return false;
    
    return true;
}

int sys_read(int fd, void* buf, size_t count)
{
    file_t* file;
    ssize_t result;
    
    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    if (!can_read(file)) return -EBADF;
    
    if (!file->f_op || !file->f_op->read) return -ENOSYS;
    
    result = file->f_op->read(file, buf, count);
    return (int)result;
}

int sys_write(int fd, const void* buf, size_t count)
{
    file_t* file;
    ssize_t result = 0;
    void *kbuf = NULL;
    const void *write_buf = buf;
    bool is_fifo = false;
    bool is_char_device = false;
    
    if (count == 0) return 0;
    if (!buf) return -EFAULT;

    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    if (!can_write(file)) return -EBADF;
    if (!file->f_op || !file->f_op->write) return -ENOSYS;
    is_fifo = file->inode && S_ISFIFO(file->inode->mode);
    is_char_device = (file->inode == NULL) ||
                     (file->inode && S_ISCHR(file->inode->mode));

    if (IS_KERNEL_ADDR((uint32_t)buf)) {
        write_buf = buf;
    } else {
        kbuf = kmalloc(count);
        if (!kbuf) return -ENOMEM;

        if (copy_from_user(kbuf, buf, count) < 0) {
            kfree(kbuf);
            return -EFAULT;
        }

        write_buf = kbuf;
    }

    if (is_fifo || is_char_device) {
        result = file->f_op->write(file, write_buf, count);
    } else {
        uint32_t irq_flags = disable_interrupts_save();
        set_critical_section();

        result = file->f_op->write(file, write_buf, count);

        unset_critical_section();
        restore_interrupts(irq_flags);
    }

    if (kbuf) kfree(kbuf);

    return (int)result;
}

static int truncate_file_inode(inode_t *inode, const char *name)
{
    if (!inode || !name) return -EINVAL;
    if (S_ISDIR(inode->mode)) return -EISDIR;

    if (inode->first_cluster != 0) {
        fat32_free_cluster_chain(inode->first_cluster);
        inode->first_cluster = 0;
        inode->blocks = 0;
        fat32_update_file_by_name(name, inode->parent_cluster, 0);
    }

    inode->size = 0;
    inode->mtime = get_current_time();
    return fat32_update_file_size_in_dir(name, inode->parent_cluster, 0);
}

int sys_close(int fd)
{
    file_t* file;

    //KDEBUG("[CLOSE] fd=%d\n", fd);

    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    
    close_file(file);
    current_task->process->files[fd] = NULL;
    current_task->process->fd_flags[fd] = 0;
    
    return 0;
}

int sys_ftruncate(int fd, off_t length)
{
    file_t* file;
    int result;
    uint32_t irq_flags;

    if (length < 0) return -EINVAL;
    if (fd < 0 || fd >= MAX_FILES) return -EBADF;

    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    if (!can_write(file)) return -EBADF;
    if (!file->inode) return -EINVAL;
    if (S_ISDIR(file->inode->mode)) return -EISDIR;
    if (!file->f_op || !file->f_op->truncate) return -ENOSYS;

    irq_flags = disable_interrupts_save();
    set_critical_section();

    result = file->f_op->truncate(file, length);

    unset_critical_section();
    restore_interrupts(irq_flags);

    return result;
}

/**
 * Séparer un chemin en répertoire parent et nom de fichier
 */
int split_path(const char* full_path, char** parent_path, char** filename) {
    int len = strlen(full_path);
    int i;
    
    /* Trouver le dernier '/' */
    for (i = len - 1; i >= 0; i--) {
        if (full_path[i] == '/') break;
    }
    
    if (i < 0) {
        /* Pas de '/', fichier dans le répertoire courant */
        *parent_path = strdup(".");
        *filename = strdup(full_path);
    } else if (i == 0) {
        /* Fichier dans la racine */
        *parent_path = strdup("/");
        *filename = strdup(full_path + 1);
    } else {
        /* Fichier dans un sous-répertoire */
        *parent_path = kmalloc(i + 1);
        if (!*parent_path) return -ENOMEM;
        
        strncpy(*parent_path, full_path, i);
        (*parent_path)[i] = '\0';
        
        *filename = strdup(full_path + i + 1);
    }
    
    if (!*filename) {
        kfree(*parent_path);
        return -ENOMEM;
    }
    
    return 0;
}



int kernel_open(char* kernel_path, int flags, mode_t mode)
{
    inode_t* inode;
    file_t* file;
    int fd;
    char* filename = NULL;
    char opened_name[256];
    bool opened_existing;

    opened_name[0] = '\0';
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    /* Find inode */
    inode = (flags & O_NOFOLLOW) ? path_lookup_ex(kernel_path, false)
                                 : path_lookup(kernel_path);
    opened_existing = inode != NULL;
    //kfree(kernel_path);
    
/*     if (!inode) {
        if (flags & O_CREAT) {
            // TODO: Create file 
            return -ENOSYS;
        }
        return -ENOENT;
    } */

    {
        char* slash = strrchr(kernel_path, '/');
        const char* base = slash ? slash + 1 : kernel_path;
        strncpy(opened_name, base, sizeof(opened_name) - 1);
        opened_name[sizeof(opened_name) - 1] = '\0';
    }

    if (inode && (flags & O_NOFOLLOW) && S_ISLNK(inode->mode)) {
        put_inode(inode);
        kfree(kernel_path);
        return -ELOOP;
    }

    if (!inode) {
        //KDEBUG("kernel_open: INODE IS NULL for %s\n", kernel_path);
        if (flags & O_CREAT) {
            char* parent_path;

            if (flags & O_DIRECTORY) {
                kfree(kernel_path);
                return -EINVAL;
            }
            
            /* Séparer le chemin */
            if (split_path(kernel_path, &parent_path, &filename) != 0) {
                kfree(kernel_path);
                return -ENOMEM;
            }
            
            /* Vérifier que le fichier n'existe pas déjà */
            inode_t* parent = path_lookup(parent_path);
            if (!parent) {
                kfree(parent_path);
                kfree(filename);
                kfree(kernel_path);
                return -ENOENT;
            }

            if (!S_ISDIR(parent->mode)) {
                put_inode(parent);
                kfree(parent_path);
                kfree(filename);
                kfree(kernel_path);
                return -ENOTDIR;
            }

            if (!inode_permission(parent, MAY_WRITE | MAY_EXEC)) {
                put_inode(parent);
                kfree(parent_path);
                kfree(filename);
                kfree(kernel_path);
                return -EACCES;
            }

            if (!filename[0] || strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
                put_inode(parent);
                kfree(parent_path);
                kfree(filename);
                kfree(kernel_path);
                return -EINVAL;
            }

            if (parent->i_op != &fat32_inode_ops && parent->i_op != &ext2_inode_ops) {
                put_inode(parent);
                kfree(parent_path);
                kfree(filename);
                kfree(kernel_path);
                return -EROFS;
            }

            if (parent->i_op == &fat32_inode_ops && fat32_file_exists_in_dir(parent, filename)) {
                if (flags & O_EXCL) {
                    /* O_CREAT | O_EXCL = échec si existe */
                    put_inode(parent);
                    kfree(parent_path);
                    kfree(filename);
                    kfree(kernel_path);
                    return -EEXIST;
                }
                
                /* Fichier existe, l'ouvrir normalement */
                char* full_path_again = kernel_path; 
                inode = path_lookup(full_path_again);
                put_inode(parent);
                kfree(parent_path);
                kfree(filename);
                filename = NULL;
            } else {
                /* Créer le nouveau fichier */
                if (current_task && current_task->process)
                    mode &= ~current_task->process->umask;

                if (parent->i_op == &fat32_inode_ops) {
                    inode = fat32_create_file(parent_path, filename, mode);
                } else {
                    inode = ext2_create_file(parent, filename, mode);
                }

                if (parent) put_inode(parent);
                kfree(parent_path);
                
                if (!inode) {
                    kfree(kernel_path);
                    return -EIO;  /* Échec création */
                }
            }
        } else {
            kfree(kernel_path);
            return -ENOENT;
        }
    }
    else{
        // File exists
        // If O_CREAT && 0_EXCL then return error
        if((flags & O_CREAT) && (flags & O_EXCL)) {
            kfree(kernel_path);
            return -EEXIST;
        }

    }
    
    kfree(kernel_path);
    
    /* Check permissions */
    if (!check_file_permission(inode, flags)) {
        put_inode(inode);
        return -EACCES;
    }

    if ((flags & O_DIRECTORY) && !S_ISDIR(inode->mode)) {
        put_inode(inode);
        return -ENOTDIR;
    }

    if (opened_existing &&
        (flags & O_TRUNC) && ((flags & O_ACCMODE) != O_RDONLY)) {
        int truncate_result;

        if (inode->f_op == &fat32_file_ops) {
            truncate_result = truncate_file_inode(inode, opened_name);
        } else if (inode->f_op == &ext2_file_ops) {
            truncate_result = ext2_truncate_inode(inode);
        } else {
            truncate_result = -EROFS;
        }

        if (truncate_result < 0) {
            put_inode(inode);
            return truncate_result;
        }
    }
    
    /* Allocate file descriptor */
    fd = allocate_fd(current_task);
    if (fd < 0) {
        put_inode(inode);
        return -EMFILE;
    }
    
    /* Create file structure */
    file = create_file();
    if (!file) {
        put_inode(inode);
        return -ENOMEM;
    }
    
    file->inode = inode;
    file->flags = flags & ~O_CLOEXEC;

    if (flags & O_APPEND) {
        //KDEBUG("APPEND FLAG DETECTED offset = %d...\n", inode->size);
        file->offset = inode->size;
    }
    else {
        file->offset = 0;
    }

    file->f_op = inode->f_op;

    if (filename) {
        strcpy(file->name, filename);
        kfree(filename);
    } else {
        strncpy(file->name, opened_name, sizeof(file->name) - 1);
        file->name[sizeof(file->name) - 1] = '\0';
    }
    
    /* Open file */
    if (file->f_op && file->f_op->open) {
        int result = file->f_op->open(inode, file);
        //KDEBUG("kernel_open: File opnened %s with result = %d\n", file->name, result);

        if (result < 0) {
            close_file(file);
            return result;
        }
    }
    
    current_task->process->files[fd] = file;
    current_task->process->fd_flags[fd] = flags & O_CLOEXEC;
    return fd;
}

char *get_current_working_directory(void){

    task_t *task = current_task;
    
    if(!task || !task->process) return NULL;

    return strdup(task->process->cwd);
}


/* Normalise un chemin absolu en place : résout . et .. composant par composant. */
void path_canonicalize(char *path) {
    const char *segs[64];
    int depth = 0;
    const char *p = path + 1;

    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);

        if (len == 0 || (len == 1 && seg[0] == '.')) {
            /* ignore . et slashs multiples */
        } else if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth > 0) depth--;   /* remonte d'un niveau (plancher = racine) */
        } else {
            segs[depth++] = seg;
        }
        if (*p == '/') p++;
    }

    /* Reconstruction en place (toujours plus court ou égal à l'original) */
    char *out = path + 1;
    for (int i = 0; i < depth; i++) {
        if (i > 0) *out++ = '/';
        const char *s = segs[i];
        while (*s && *s != '/') *out++ = *s++;
    }
    *out = '\0';
}

char* resolve_path(const char* path) {
    char* full_path;
    char* cwd;
    size_t cwd_len, path_len;

    if (path[0] == '/') {
        char* abs = strdup(path);
        if (abs) path_canonicalize(abs);
        return abs;
    }

    /* Chemin relatif (y compris ".", "..", "./foo", "../foo") : préfixer avec cwd */
    cwd = get_current_working_directory();
    if (!cwd) return NULL;

    cwd_len = strlen(cwd);
    path_len = strlen(path);

    full_path = kmalloc(cwd_len + 1 + path_len + 1);
    if (!full_path) {
        kfree(cwd);
        return NULL;
    }

    strcpy(full_path, cwd);
    if (cwd[cwd_len - 1] != '/') {
        strcat(full_path, "/");
    }
    strcat(full_path, path);

    path_canonicalize(full_path);
    kfree(cwd);
    return full_path;
}

int sys_open(const char* pathname, int flags, mode_t mode)
{
    char* kernel_path;
    char* full_path;
    file_t* tty_file;
    file_t* null_file;
    file_t* net_echo_file;

    int fd;

    /* Suppression du warning unused parameter */
    (void)mode;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    //KDEBUG("sys_open: opening file %s, kernel_path = %s, flags = %d\n", pathname, kernel_path, flags);
    /* Résoudre le chemin (absolu ou relatif) */
    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    
    if (!full_path) return -ENOENT;

    if (is_tty_device_path(full_path)) {
        int tty_id = tty_id_from_device_path(full_path);

        if (tty_id < 0) {
            int ret = tty_id;
            kfree(full_path);
            return ret;
        }

        if (!tty_has_backend_for_id(tty_id)) {
            kfree(full_path);
            return -ENODEV;
        }

        fd = allocate_fd(current_task);
        if (fd < 0) {
            kfree(full_path);
            return fd;
        }

        tty_file = create_tty_console_file(
            strcmp(full_path, "/dev/tty") == 0 ? "tty" :
            strcmp(full_path, "/dev/console") == 0 ? "console" :
            strcmp(full_path, "/dev/tty1") == 0 ? "tty1" : "tty0",
            flags & ~O_CLOEXEC);
        if (!tty_file) {
            free_fd(current_task, fd);
            kfree(full_path);
            return -ENOMEM;
        }

        current_task->process->files[fd] = tty_file;
        current_task->process->fd_flags[fd] = flags & O_CLOEXEC;
        kfree(full_path);
        return fd;
    }

    if (is_null_device_path(full_path)) {
        if (flags & O_DIRECTORY) {
            kfree(full_path);
            return -ENOTDIR;
        }

        fd = allocate_fd(current_task);
        if (fd < 0) {
            kfree(full_path);
            return fd;
        }

        null_file = create_null_device_file("null", flags & ~O_CLOEXEC);
        if (!null_file) {
            free_fd(current_task, fd);
            kfree(full_path);
            return -ENOMEM;
        }

        current_task->process->files[fd] = null_file;
        current_task->process->fd_flags[fd] = flags & O_CLOEXEC;
        kfree(full_path);
        return fd;
    }

    if (is_net_echo_device_path(full_path)) {
        if (flags & O_DIRECTORY) {
            kfree(full_path);
            return -ENOTDIR;
        }

        fd = allocate_fd(current_task);
        if (fd < 0) {
            kfree(full_path);
            return fd;
        }

        net_echo_file = create_net_echo_device_file("netecho", flags & ~O_CLOEXEC);
        if (!net_echo_file) {
            free_fd(current_task, fd);
            kfree(full_path);
            return -ENODEV;
        }

        current_task->process->files[fd] = net_echo_file;
        current_task->process->fd_flags[fd] = flags & O_CLOEXEC;
        kfree(full_path);
        return fd;
    }

    fd = kernel_open(full_path, flags, mode);

    //KDEBUG("sys_open: '%s' flags=0x%x -> fd=%d\n", pathname, flags, fd);
  

    return fd;
}

int sys_creat(const char* pathname, mode_t mode)
{
    return sys_open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

off_t sys_lseek(int fd, off_t offset, int whence)
{
    file_t* file;
    off_t new_offset;
    
    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    
    if (file->f_op && file->f_op->lseek) {
        return file->f_op->lseek(file, offset, whence);
    }
    
    /* Default lseek implementation */
    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = file->offset + offset;
            break;
        case SEEK_END:
            new_offset = (off_t)file->inode->size + offset;
            break;
        default:
            return -EINVAL;
    }
    
    if (new_offset < 0) {
        return -EINVAL;
    }
    
    file->offset = new_offset;
    return new_offset;
}

static void fill_stat_from_inode(struct stat* kstat, inode_t* inode)
{
    memset(kstat, 0, sizeof(*kstat));
    kstat->st_dev = 0;      /* TODO: expose VFS mount/device id */
    kstat->st_ino = inode->first_cluster ? inode->first_cluster : inode->ino;
    kstat->st_mode = inode->mode;
    kstat->st_nlink = inode->nlink ? inode->nlink : 1;
    kstat->st_uid = inode->uid;
    kstat->st_gid = inode->gid;
    kstat->st_rdev = (S_ISCHR(inode->mode) || S_ISBLK(inode->mode)) ? inode->parent_cluster : 0;
    kstat->st_size = inode->size;
    kstat->st_blksize = 1024;
    kstat->st_blocks = (S_ISCHR(inode->mode) || S_ISBLK(inode->mode)) ? 0 :
        (inode->blocks ? inode->blocks : (inode->size + 511) / 512);
    kstat->st_atime = inode->atime;
    kstat->st_mtime = inode->mtime;
    kstat->st_ctime = inode->ctime;
}

int sys_stat(const char* pathname, struct stat* statbuf)
{
    char* kernel_path;
    inode_t* inode;
    struct stat kstat;
    char* full_path;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    /* Résoudre le chemin (absolu ou relatif) */
    full_path = resolve_path(kernel_path);
    kfree(kernel_path);

    if (!full_path) return -ENOENT;

    if (is_null_device_path(full_path)) {
        fill_null_device_stat(&kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }

    if (is_tty_device_path(full_path)) {
        fill_tty_device_stat(full_path, &kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }

    if (is_net_echo_device_path(full_path)) {
        fill_net_echo_device_stat(&kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }
    
    inode = path_lookup(full_path);
    kfree(full_path);
    
    if (!inode) return -ENOENT;
    
    fill_stat_from_inode(&kstat, inode);
    
    /* Copy to user space */
    if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
        put_inode(inode);
        return -EFAULT;
    }
    
    put_inode(inode);
    return 0;
}

int sys_lstat(const char* pathname, struct stat* statbuf)
{
    char* kernel_path;
    inode_t* inode;
    struct stat kstat;
    char* full_path;

    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    if (!full_path) return -ENOENT;

    if (is_null_device_path(full_path)) {
        fill_null_device_stat(&kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }

    if (is_tty_device_path(full_path)) {
        fill_tty_device_stat(full_path, &kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }

    if (is_net_echo_device_path(full_path)) {
        fill_net_echo_device_stat(&kstat);
        kfree(full_path);
        if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
            return -EFAULT;
        }
        return 0;
    }

    inode = path_lookup_ex(full_path, false);
    kfree(full_path);

    if (!inode) return -ENOENT;

    fill_stat_from_inode(&kstat, inode);

    if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
        put_inode(inode);
        return -EFAULT;
    }

    put_inode(inode);
    return 0;
}

int sys_fstat(int fd, struct stat* statbuf)
{

    inode_t* inode;
    struct stat kstat;
    file_t* file;

    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    
    inode = file->inode;
    if (!inode) return -ENOENT;
    
    fill_stat_from_inode(&kstat, inode);
    
    /* Copy to user space */
    if (copy_to_user(statbuf, &kstat, sizeof(struct stat)) < 0) {
        return -EFAULT;
    }
    
    return 0;
}

/* Helper functions */
file_t* create_file(void)
{
    file_t* file = kmalloc(sizeof(file_t));
    if (file) {
        memset(file, 0, sizeof(file_t));
        file->type = FILE_TYPE_REGULAR;
        file->ref_count = 1;
    }
    return file;
}

bool file_is_tty(file_t* file)
{
    return file && file->type == FILE_TYPE_TTY;
}

file_t* get_file(file_t* file)
{
    unsigned long flags;

    if (!file) return NULL;

    spin_lock_irqsave(&file_ref_lock, &flags);
    if (file->ref_count == 0) {
        spin_unlock_irqrestore(&file_ref_lock, flags);
        return NULL;
    }
    file->ref_count++;
    spin_unlock_irqrestore(&file_ref_lock, flags);

    return file;
}

void close_file(file_t* file)
{
    bool do_close = false;
    unsigned long flags;

    if (!file) return;

    spin_lock_irqsave(&file_ref_lock, &flags);
    if (file->ref_count == 0) {
        spin_unlock_irqrestore(&file_ref_lock, flags);
        KERROR("close_file: invalid zero refcount for file %p\n", file);
        return;
    }
    
    file->ref_count--;
    do_close = (file->ref_count == 0);
    spin_unlock_irqrestore(&file_ref_lock, flags);

    if (do_close) {
        if (file->f_op && file->f_op->close)
            file->f_op->close(file);
        if (file->inode)
            put_inode(file->inode);
        kfree(file);
    }
}

static bool check_file_permission(inode_t* inode, int flags)
{
    int mask = 0;

    if (!inode)
        return false;

    /*
     * POSIX open() access bits are not permission bits. Translate the requested
     * file access into the inode permission model used by access() and execve().
     * O_TRUNC also needs write permission, even if a buggy caller forgot to use
     * O_WRONLY/O_RDWR.
     */
    switch (flags & O_ACCMODE) {
        case O_RDONLY:
            mask |= MAY_READ;
            break;
        case O_WRONLY:
            mask |= MAY_WRITE;
            break;
        case O_RDWR:
            mask |= MAY_READ | MAY_WRITE;
            break;
        default:
            return false;
    }

    if (flags & O_TRUNC)
        mask |= MAY_WRITE;

    return inode_permission(inode, mask);
}


int sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {
    file_t *file;
    char *user_buf = (char *)dirp;
    char *buf_ptr = user_buf;
    size_t bytes_written = 0;

    //KDEBUG("[GETDENTS] entry fd=%u dirp=%p count=%u\n", fd, dirp, count);

    /* Vérifier le fd */
    if (fd >= MAX_FILES || !current_task->process->files[fd]) {
        KERROR("[GETDENTS] EBADF fd=%u files[fd]=%p\n", fd,
               fd < MAX_FILES ? (void*)current_task->process->files[fd] : NULL);
        return -EBADF;
    }
    
    file = current_task->process->files[fd];
    
    /* Vérifier que c'est un répertoire */
    if (!file->inode || !S_ISDIR(file->inode->mode)) {
        return -ENOTDIR;
    }
    
    /* Vérifier que le buffer est valide */
    if (!user_buf || count < sizeof(struct linux_dirent)) {
        return -EINVAL;
    }
    
    //KDEBUG("Reading entries from %s fd=%d\n", file->name, fd);

    /* Vérifier que f_op et readdir sont valides */
    if (!file->f_op || !file->f_op->readdir) {
        KERROR("[GETDENTS] fd=%u: f_op=%p readdir=%p\n",
               fd, file->f_op,
               file->f_op ? (void*)file->f_op->readdir : NULL);
        return -ENOSYS;
    }

    //KDEBUG("[GETDENTS] fd=%u file=%p inode=%p f_op=%p readdir=%p\n",
    //       fd, file, file->inode, file->f_op, file->f_op->readdir);

    /* Lire les entrées du répertoire */
    while (bytes_written < count) {
        struct dirent entry;
        struct linux_dirent *dirent;
        size_t name_len;
        size_t rec_len;
        uint32_t saved_offset;

        /* Lire une entrée via le VFS */
        saved_offset = file->offset;
        ssize_t ret = file->f_op->readdir(file, &entry);
        
        if (ret <= 0) {
            /* Fin du répertoire ou erreur */
            break;
        }

        /* Calculer la taille de l'entrée */
        name_len = strlen(entry.d_name);
        rec_len = offsetof(struct linux_dirent, d_name) + name_len + 1 ;
        rec_len = (rec_len + 7) & ~7;  /* Aligner sur 4 bytes */

        /* Vérifier qu'il reste assez de place */
        if (bytes_written + rec_len > count) {
            /* Reculer la position de lecture pour cette entrée */
            file->offset = saved_offset;
            break;
        }
        
        /* Construire l'entrée linux_dirent */
        dirent = (struct linux_dirent *)buf_ptr;
        
        dirent->d_ino = entry.d_ino;
        dirent->d_off = file->offset;
        dirent->d_reclen = rec_len;
        dirent->d_type = entry.d_type;
        
        /* Copier le nom */
        memcpy(dirent->d_name, entry.d_name, name_len + 1);
        
        buf_ptr += rec_len;
        bytes_written += rec_len;
    }
    
    return bytes_written;
}

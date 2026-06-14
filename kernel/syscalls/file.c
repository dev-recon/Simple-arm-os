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
#include <kernel/timer.h>
#include <kernel/dirent.h>
#include <asm/mmu.h>


/* Forward declarations de toutes les fonctions statiques */
static bool check_file_permission(inode_t* inode, int flags);
extern int fat32_file_exists_in_dir(inode_t* dir_inode, const char* filename);
extern inode_t* fat32_create_file(const char* parent_path, const char* filename, mode_t mode);
extern void fat32_free_cluster_chain(uint32_t start_cluster);
extern int fat32_update_file_by_name(const char* filename, uint32_t parent_cluster, uint32_t new_cluster);
extern int fat32_update_file_size_in_dir(const char* filename, uint32_t parent_cluster, uint32_t new_size);

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
    
    if (count == 0) return 0;
    if (!buf) return -EFAULT;

    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    if (!file->f_op || !file->f_op->write) return -ENOSYS;

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

    uint32_t irq_flags = disable_interrupts_save();
    set_critical_section();

    result = file->f_op->write(file, write_buf, count);

    unset_critical_section();
    restore_interrupts(irq_flags);

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
    
    return 0;
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

    opened_name[0] = '\0';
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    /* Find inode */
    inode = path_lookup(kernel_path);
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

    if (!inode) {
        //KDEBUG("kernel_open: INODE IS NULL for %s\n", kernel_path);
        if (flags & O_CREAT) {
            char* parent_path;
            
            /* Séparer le chemin */
            if (split_path(kernel_path, &parent_path, &filename) != 0) {
                kfree(kernel_path);
                return -ENOMEM;
            }
            
            /* Vérifier que le fichier n'existe pas déjà */
            inode_t* parent = path_lookup(parent_path);
            if (parent && fat32_file_exists_in_dir(parent, filename)) {
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
            } else {
                /* Créer le nouveau fichier */
                if (current_task && current_task->process)
                    mode &= ~current_task->process->umask;

                inode = fat32_create_file(parent_path, filename, mode);
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

        if ((flags & O_TRUNC) && ((flags & O_ACCMODE) != O_RDONLY)) {
            int truncate_result = truncate_file_inode(inode, opened_name);
            if (truncate_result < 0) {
                put_inode(inode);
                kfree(kernel_path);
                return truncate_result;
            }
        }
    }
    
    kfree(kernel_path);
    
    /* Check permissions */
    if (!check_file_permission(inode, flags)) {
        put_inode(inode);
        return -EACCES;
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
    file->flags = flags;

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

    fd = kernel_open(full_path, flags, mode);

    //KDEBUG("sys_open: '%s' flags=0x%x -> fd=%d\n", pathname, flags, fd);
  

    return fd;
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
    
    inode = path_lookup(full_path);
    kfree(full_path);
    
    if (!inode) return -ENOENT;
    
    /* Fill stat structure */
    memset(&kstat, 0, sizeof(kstat));
    kstat.st_ino = inode->ino;
    kstat.st_mode = inode->mode;
    kstat.st_nlink = 1;
    kstat.st_uid = inode->uid;
    kstat.st_gid = inode->gid;
    kstat.st_size = inode->size;
    kstat.st_atime = inode->atime;
    kstat.st_mtime = inode->mtime;
    kstat.st_ctime = inode->ctime;
    
    /* Copy to user space */
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
    
    /* Fill stat structure */
    memset(&kstat, 0, sizeof(kstat));
    kstat.st_ino = inode->ino;
    kstat.st_mode = inode->mode;
    kstat.st_nlink = 1;
    kstat.st_uid = inode->uid;
    kstat.st_gid = inode->gid;
    kstat.st_size = inode->size;
    kstat.st_atime = inode->atime;
    kstat.st_mtime = inode->mtime;
    kstat.st_ctime = inode->ctime;
    
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
        file->ref_count = 1;
    }
    return file;
}

void close_file(file_t* file)
{
    if (!file) return;

    if (file->ref_count == 0) {
        KERROR("close_file: invalid zero refcount for file %p\n", file);
        return;
    }
    
    file->ref_count--;
    if (file->ref_count == 0) {
        if (file->f_op && file->f_op->close) {
            file->f_op->close(file);
        }
        if (file->inode) {
            put_inode(file->inode);
        }
        kfree(file);
    }
}

static bool check_file_permission(inode_t* inode, int flags)
{
    /* Suppression des warnings unused parameter */
    (void)inode;
    (void)flags;
    
    /* TODO: Implement proper permission checking */
    return true;
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

        /* Lire une entrée via le VFS */
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
            file->offset--;
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

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


/* Forward declarations de toutes les fonctions statiques */
static bool check_file_permission(inode_t* inode, int flags);
extern int fat32_file_exists_in_dir(inode_t* dir_inode, const char* filename);
extern inode_t* fat32_create_file(const char* parent_path, const char* filename, mode_t mode);

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

    char *loc_string = NULL;
    
    if(!buf || count == 0) return -EINVAL;

    if (fd < 0 || fd >= MAX_FILES) return -EBADF;
    
    file = current_task->process->files[fd];
    if (!file) return -EBADF;
    
    if (!file->f_op || !file->f_op->write) return -ENOSYS;


    //KDEBUG("SYS_WRITE: buf is NOT NULL\n");

    loc_string = (char *)kmalloc(count+1);
    if(!loc_string) return -EINVAL;

    uint32_t irq_flags = disable_interrupts_save();
    set_critical_section();

    if(strncpy_from_user(loc_string, buf, count+1)>0)
    {
        //KDEBUG("SYS_WRITE USER: Called with parameters: fd=%d, buf='%s', count=%d\n", fd, loc_string, count );

        //if(loc_string) kfree(loc_string);

        result = file->f_op->write(file, loc_string, count);

        kfree(loc_string);
    }
    else {
        //KDEBUG("SYS_WRITE KERNEL: Called with parameters: fd=%d, buf='%s', count=%d\n", fd, (char *)buf, count );
        result = file->f_op->write(file, buf, count);
    }

    unset_critical_section();
    restore_interrupts(irq_flags);

    //KDEBUG("SYS_WRITE: just after writing result = %d\n" , result);

    return (int)result;
}

int sys_close(int fd)
{
    file_t* file;
    
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
    bool new_file = false;
    
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
                inode = fat32_create_file(parent_path, filename, mode);
                if (parent) put_inode(parent);
                kfree(parent_path);
                new_file = true;
                
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
    file->offset = 0;
    file->f_op = inode->f_op;

    if(new_file)
    {
        strcpy(file->name, filename);
        //KDEBUG("kernel_open: File creation detected: file->name=%s\n", file->name);
        kfree(filename);
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


char* resolve_path(const char* path) {
    char* full_path;
    char* cwd;
    size_t cwd_len, path_len;
    
    /* Si chemin absolu, retourner une copie */
    if (path[0] == '/') {
        return strdup(path);
    }
    
    /* Chemin relatif - obtenir le répertoire courant */
    cwd = get_current_working_directory();
    if (!cwd) return NULL;
    
    cwd_len = strlen(cwd);
    path_len = strlen(path);
    
    /* Allouer pour "cwd/path\0" */
    full_path = kmalloc(cwd_len + 1 + path_len + 1);
    if (!full_path) {
        kfree(cwd);
        return NULL;
    }
    
    /* Construire le chemin complet */
    strcpy(full_path, cwd);
    if (cwd[cwd_len - 1] != '/') {
        strcat(full_path, "/");
    }
    strcat(full_path, path);
    
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

    //KDEBUG("sys_open: opening file %s, kernel_path = %s\n", pathname, kernel_path);
    /* Résoudre le chemin (absolu ou relatif) */
    full_path = resolve_path(kernel_path);
    kfree(kernel_path);
    
    if (!full_path) return -ENOENT;

    fd = kernel_open(full_path, flags, mode);

    //KDEBUG("sys_open: opened file fd = %d\n", fd);
  

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



#include <kernel/task.h>
#include <kernel/syscalls.h>
#include <kernel/vfs.h>
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/userspace.h>
#include <kernel/kprintf.h>


/* Forward declarations de toutes les fonctions statiques */
static bool check_file_permission(inode_t* inode, int flags);


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

    strncpy_from_user(loc_string, buf, count+1);

    //KDEBUG("SYS_WRITE: Called with parameters: fd=%d, buf='%s', count=%d\n", fd, loc_string, count );

    //if(loc_string) kfree(loc_string);
    
    result = file->f_op->write(file, loc_string, count);

    //KDEBUG("SYS_WRITE: just after writing result = %d\n" , result);
    kfree(loc_string);

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

int kernel_open(char* kernel_path, int flags, mode_t mode)
{
    inode_t* inode;
    file_t* file;
    int fd;
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    /* Find inode */
    inode = path_lookup(kernel_path);
    kfree(kernel_path);
    
    if (!inode) {
        if (flags & O_CREAT) {
            /* TODO: Create file */
            return -ENOSYS;
        }
        return -ENOENT;
    }
    
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
    
    /* Open file */
    if (file->f_op && file->f_op->open) {
        int result = file->f_op->open(inode, file);
        if (result < 0) {
            close_file(file);
            return result;
        }
    }
    
    current_task->process->files[fd] = file;
    return fd;
}


int sys_open(const char* pathname, int flags, mode_t mode)
{
    char* kernel_path;
 
    int fd;
    
    /* Suppression du warning unused parameter */
    (void)mode;
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;

    KDEBUG("sys_open: opening file %s, kernel_path = %s\n", pathname, kernel_path);
    
    fd = kernel_open(kernel_path, flags, mode);

    KDEBUG("sys_open: opened file fd = %d\n", fd);
  

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
    
    kernel_path = copy_string_from_user(pathname);
    if (!kernel_path) return -EFAULT;
    
    inode = path_lookup(kernel_path);
    kfree(kernel_path);
    
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



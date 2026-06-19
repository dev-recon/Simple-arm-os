/* kernel/drivers/null.c - /dev/null character device */
#include <kernel/null.h>
#include <kernel/vfs.h>
#include <kernel/file.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/timer.h>

extern file_t* create_file(void);
extern inode_t* create_inode(void);
extern void put_inode(inode_t* inode);

static ssize_t null_read(file_t* file, void* buffer, size_t count)
{
    (void)file;
    (void)buffer;
    (void)count;
    return 0;
}

static ssize_t null_write(file_t* file, const void* buffer, size_t count)
{
    (void)file;
    (void)buffer;
    return (ssize_t)count;
}

static off_t null_lseek(file_t* file, off_t offset, int whence)
{
    (void)file;
    (void)offset;
    (void)whence;
    return 0;
}

static file_operations_t null_file_ops = {
    .read = null_read,
    .write = null_write,
    .open = NULL,
    .close = NULL,
    .lseek = null_lseek,
    .readdir = NULL,
    .truncate = NULL,
};

bool is_null_device_path(const char* path)
{
    return path && strcmp(path, "/dev/null") == 0;
}

void fill_null_device_stat(struct stat* st)
{
    uint32_t now;

    if (!st) return;

    now = get_current_time();
    memset(st, 0, sizeof(*st));
    st->st_dev = 0;
    st->st_ino = DEV_NULL_RDEV;
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_rdev = DEV_NULL_RDEV;
    st->st_size = 0;
    st->st_blksize = 1024;
    st->st_blocks = 0;
    st->st_atime = now;
    st->st_mtime = now;
    st->st_ctime = now;
}

file_t* create_null_device_file(const char* name, int flags)
{
    file_t* file;
    inode_t* inode;
    uint32_t now;

    file = create_file();
    if (!file) return NULL;

    inode = create_inode();
    if (!inode) {
        kfree(file);
        return NULL;
    }

    now = get_current_time();
    inode->mode = S_IFCHR | 0666;
    inode->uid = 0;
    inode->gid = 0;
    inode->size = 0;
    inode->blocks = 0;
    inode->nlink = 1;
    inode->first_cluster = 0;
    inode->parent_cluster = DEV_NULL_RDEV;
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;
    inode->i_op = NULL;
    inode->f_op = &null_file_ops;

    file->f_op = &null_file_ops;
    file->flags = flags;
    file->type = FILE_TYPE_NULL;
    file->pos = 0;
    file->offset = 0;
    file->inode = inode;

    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1);
        file->name[sizeof(file->name) - 1] = '\0';
    }

    return file;
}

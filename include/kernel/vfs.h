/* include/kernel/vfs.h */
#ifndef _KERNEL_VFS_H
#define _KERNEL_VFS_H

#include <kernel/types.h>
#include <kernel/task.h>

/* Forward declarations */
struct process;

/* File types */
#define S_IFMT      0170000
#define S_IFREG     0100000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFBLK     0060000
#define S_IFIFO     0010000
#define S_IFLNK     0120000

#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)

/* Permissions */
#define S_IRWXU     0000700
#define S_IRUSR     0000400
#define S_IWUSR     0000200
#define S_IXUSR     0000100
#define S_IRWXG     0000070
#define S_IRGRP     0000040
#define S_IWGRP     0000020
#define S_IXGRP     0000010
#define S_IRWXO     0000007
#define S_IROTH     0000004
#define S_IWOTH     0000002
#define S_IXOTH     0000001

/* Open flags */
#define O_RDONLY    0000000
#define O_WRONLY    0000001
#define O_RDWR      0000002
#define O_CREAT     0000100
#define O_EXCL      0000200
#define O_TRUNC     0001000
#define O_APPEND    0002000
#define O_CLOEXEC   0020000

/* Seek whence */
#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

/* Directory entry types */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12
#define DT_WHT      14



/* VFS functions */
bool init_vfs(void);
inode_t* create_inode(void);
inode_t* get_inode(uint32_t ino);
inode_t* get_root_inode(void);
void put_inode(inode_t* inode);
inode_t* path_lookup(const char* path);

/* File descriptor management */
void free_fd(task_t* proc, int fd);
int allocate_fd(task_t* process);

/* File operations */
void close_file(file_t* file);

/* User space memory functions */
int copy_to_user(void* to, const void* from, size_t n);
int copy_from_user(void* to, const void* from, size_t n);
bool is_valid_user_ptr(const void* ptr);

/* File creation */
file_t* create_file(void);
void close_file(file_t* file);

uint32_t get_next_inode_number(void);

/* Helper functions */


/* NOTE: Ces fonctions sont implementees dans les fichiers syscalls,
 * pas dans VFS, pour eviter les conflits de declaration */

#endif
#ifndef _SYS_STAT_H
#define _SYS_STAT_H

#include <sys/types.h>
#include <stddef.h>

/* Structure stat */
struct stat {
    dev_t     st_dev;       /* Device ID */
    ino_t     st_ino;       /* Inode number */
    mode_t    st_mode;      /* File type and mode */
    nlink_t   st_nlink;     /* Number of hard links */
    uid_t     st_uid;       /* User ID of owner */
    gid_t     st_gid;       /* Group ID of owner */
    dev_t     st_rdev;      /* Device ID (if special file) */
    off_t     st_size;      /* Total size, in bytes */
    blksize_t st_blksize;   /* Block size for filesystem I/O */
    blkcnt_t  st_blocks;    /* Number of 512B blocks allocated */
    time_t    st_atime;     /* Time of last access */
    time_t    st_mtime;     /* Time of last modification */
    time_t    st_ctime;     /* Time of last status change */
};


/* Constantes pour st_mode */
#define S_IFMT      0170000   /* Type mask */
#define S_IFSOCK    0140000   /* Socket */
#define S_IFLNK     0120000   /* Symbolic link */
#define S_IFREG     0100000   /* Regular file */
#define S_IFBLK     0060000   /* Block device */
#define S_IFDIR     0040000   /* Directory */
#define S_IFCHR     0020000   /* Character device */
#define S_IFIFO     0010000   /* FIFO */

/* Macros de test de type */
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)


/* Prototypes */
int stat(const char *pathname, struct stat *statbuf);
int fstat(int fd, struct stat *statbuf);
int lstat(const char *pathname, struct stat *statbuf);
int chmod(const char *pathname, mode_t mode);
int fchmod(int fd, mode_t mode);
int mkfifo(const char *pathname, mode_t mode);

#endif /* _SYS_STAT_H */
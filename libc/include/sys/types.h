#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

/* Types de base pour stat */
typedef unsigned int    dev_t;      /* Device ID */
typedef unsigned int    ino_t;      /* Inode number */
typedef unsigned int    mode_t;     /* File mode */
typedef unsigned int    nlink_t;    /* Number of links */
typedef unsigned int    uid_t;      /* User ID */
typedef unsigned int    gid_t;      /* Group ID */
//typedef long            off_t;      /* File offset */
typedef unsigned int    blksize_t;  /* Block size */
typedef unsigned int    blkcnt_t;   /* Block count */
//typedef long            time_t;     /* Time */
typedef int             pid_t;      /* Process ID */
typedef unsigned int    size_t;     /* Size type */
typedef int             ssize_t;    /* Signed size type */

#endif /* _SYS_TYPES_H */
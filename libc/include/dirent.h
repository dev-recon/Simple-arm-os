/* kernel/include/kernel/dirent.h */
#ifndef _DIRENT_H
#define _DIRENT_H

#include <stdint.h>
#include <sys/types.h>

/* Structure utilisée par sys_getdents */
/* Structure utilisée par sys_getdents */
struct linux_dirent {
    uint32_t  d_ino;     /* Inode number */
    uint32_t  d_off;     /* Offset to next dirent */
    uint16_t  d_reclen;  /* Length of this dirent */
    uint8_t   d_type;    /* File type */
    char      d_name[];  /* Filename (null-terminated) */
    /* Note: d_type est après d_name[strlen(d_name)+1] */
};


/* Types de fichiers pour d_type */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12
#define DT_WHT      14

int getdents(int fd, void *dirp, size_t count);

#endif
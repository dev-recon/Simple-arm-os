#ifndef _FCNTL_H
#define _FCNTL_H

/* Flags pour open() */

#define O_RDONLY    0           
#define O_WRONLY    1           
#define O_RDWR      2           
#define O_ACCMODE   3           

#define O_APPEND    0x0008      /* _FAPPEND */
#define O_CREAT     0x0200      /* _FCREAT */
#define O_TRUNC     0x0400      /* _FTRUNC */
#define O_EXCL      0x0800      /* _FEXCL */
#define O_NONBLOCK  0x4000      /* _FNONBLOCK */
#define O_NOCTTY    0x8000      /* _FNOCTTY */
#define O_SYNC      0x2000      /* _FSYNC */

/* Extensions POSIX */
#define O_CLOEXEC   0x40000     /* _FNOINHERIT */
#define O_NOFOLLOW  0x100000    /* _FNOFOLLOW */
#define O_DIRECTORY 0x200000    /* _FDIRECTORY */
#define O_DIRECT    0x80000     /* _FDIRECT */

/* Flags pour lseek() */
#define SEEK_SET    0   /* Seek from beginning */
#define SEEK_CUR    1   /* Seek from current position */
#define SEEK_END    2   /* Seek from end */

/* Mode bits pour permissions */
#define S_IRWXU     0700    /* User read/write/execute */
#define S_IRUSR     0400    /* User read */
#define S_IWUSR     0200    /* User write */
#define S_IXUSR     0100    /* User execute */

#define S_IRWXG     0070    /* Group read/write/execute */
#define S_IRGRP     0040    /* Group read */
#define S_IWGRP     0020    /* Group write */
#define S_IXGRP     0010    /* Group execute */

#define S_IRWXO     0007    /* Others read/write/execute */
#define S_IROTH     0004    /* Others read */
#define S_IWOTH     0002    /* Others write */
#define S_IXOTH     0001    /* Others execute */

#endif /* _FCNTL_H */
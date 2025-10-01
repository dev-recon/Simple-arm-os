#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H

#include <kernel/task.h>

/* Accès (mutuellement exclusifs) */
#ifndef O_RDONLY
#define O_RDONLY    0x0000      /* lecture seule */
#endif
#ifndef O_WRONLY
#define O_WRONLY    0x0001      /* écriture seule */
#endif
#ifndef O_RDWR
#define O_RDWR      0x0002      /* lecture + écriture */
#endif
#ifndef O_ACCMODE
#define O_ACCMODE   0x0003      /* masque pour extraire l'accès */
#endif

/* Création / comportement */
#ifndef O_CREAT
#define O_CREAT     0x0200      /* créer si n'existe pas */
#endif
#ifndef O_EXCL
#define O_EXCL      0x0800      /* avec O_CREAT : échouer si existe */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY    0x8000      /* ne pas devenir controlling-tty */
#endif
#ifndef O_TRUNC
#define O_TRUNC     0x0400      /* tronquer à 0 si écriture */
#endif
#ifndef O_APPEND
#define O_APPEND    0x0008      /* writes ajoutent à la fin */
#endif

/* Non-bloquant / async */
#ifndef O_NONBLOCK
#define O_NONBLOCK  0x4000      /* non-bloquant */
#endif
#ifndef O_DSYNC
#define O_DSYNC     0x1000      /* écriture synchronisée des données */
#endif
#ifndef O_RSYNC
#define O_RSYNC     0x2000      /* lectures synchronisées */
#endif
#ifndef O_SYNC
#define O_SYNC      0x2000      /* écriture synchronisée */
#endif

/* Options diverses / sécurités */
#ifndef O_DIRECTORY
#define O_DIRECTORY 0x200000     /* doit être répertoire */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW  0x100000     /* ne pas suivre symlink */
#endif
#ifndef O_DIRECT
#define O_DIRECT    0x80000     /* bypass caches */
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC   0x40000     /* FD fermé au exec */
#endif

/* Modes (mode_t) — permissions POSIX */
#ifndef S_IRUSR
#define S_IRUSR     0400        /* owner read */
#endif
#ifndef S_IWUSR
#define S_IWUSR     0200        /* owner write */
#endif
#ifndef S_IXUSR
#define S_IXUSR     0100        /* owner exec */
#endif

#ifndef S_IRGRP
#define S_IRGRP     0040        /* group read */
#endif
#ifndef S_IWGRP
#define S_IWGRP     0020        /* group write */
#endif
#ifndef S_IXGRP
#define S_IXGRP     0010        /* group exec */
#endif

#ifndef S_IROTH
#define S_IROTH     0004        /* others read */
#endif
#ifndef S_IWOTH
#define S_IWOTH     0002        /* others write */
#endif
#ifndef S_IXOTH
#define S_IXOTH     0001        /* others exec */
#endif

/* Utilitaires */
#ifndef S_IRWXU
#define S_IRWXU     (S_IRUSR|S_IWUSR|S_IXUSR)  /* owner rwx */
#endif
#ifndef S_IRWXG
#define S_IRWXG     (S_IRGRP|S_IWGRP|S_IXGRP)  /* group rwx */
#endif
#ifndef S_IRWXO
#define S_IRWXO     (S_IROTH|S_IWOTH|S_IXOTH)  /* others rwx */
#endif


/* Permissions pour inode_permission */
#define MAY_EXEC    1
#define MAY_WRITE   2
#define MAY_READ    4

int split_path(const char* full_path, char** parent_path, char** filename);
bool inode_permission(inode_t* inode, int mask);

#endif /* _KERNEL_FILE_H */
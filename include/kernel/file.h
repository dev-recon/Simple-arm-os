#ifndef _KERNEL_FILE_H
#define _KERNEL_FILE_H

#include <kernel/task.h>

/* accès (mutuellement exclusifs) */
#ifndef O_RDONLY
#define O_RDONLY    0       /* lecture seule */
#endif
#ifndef O_WRONLY
#define O_WRONLY    1       /* écriture seule */
#endif
#ifndef O_RDWR
#define O_RDWR      2       /* lecture + écriture */
#endif
#ifndef O_ACCMODE
#define O_ACCMODE   0003    /* masque pour extraire l'accès (O_RDONLY/O_WRONLY/O_RDWR) */
#endif

/* création / comportement */
#ifndef O_CREAT
#define O_CREAT     0100    /* créer si n'existe pas (octal 0x40) */
#endif
#ifndef O_EXCL
#define O_EXCL      0200    /* avec O_CREAT : échouer si existe (0x80) */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY    0400    /* ne pas devenir controlling-tty (0x100) */
#endif
#ifndef O_TRUNC
#define O_TRUNC     01000   /* tronquer à 0 si écriture (0x200) */
#endif
#ifndef O_APPEND
#define O_APPEND    02000   /* writes ajoutent à la fin (0x400) */
#endif

/* non-bloquant / async */
#ifndef O_NONBLOCK
#define O_NONBLOCK  04000   /* non-bloquant (0x800) */
#endif
#ifndef O_DSYNC
#define O_DSYNC     010000  /* écriture synchronisée des données (0x1000) */
#endif
#ifndef O_SYNC
#define O_SYNC      040000  /* écriture synchronisée (dépend de la plate-forme) */
#endif
#ifndef O_RSYNC
#define O_RSYNC     020000  /* lectures synchronisées (rare) */
#endif

/* options diverses / sécurités */
#ifndef O_DIRECTORY
#define O_DIRECTORY 0200000 /* doit être répertoire (0x40000) */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW  0400000 /* ne pas suivre le dernier composant s'il est symlink (0x80000) */
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC   02000000/* FD fermé au exec (0x800000) — verify on your platform */
#endif

/* flags supplémentaires parfois utiles */
#ifndef O_DIRECT
#define O_DIRECT    040000  /* bypass caches (plateforme dépendant) */
#endif
#ifndef O_TMPFILE
#define O_TMPFILE   0x410000 /* impl. dépendante — traite avec prudence */
#endif

/* Modes (mode_t) — permissions POSIX (utiles si O_CREAT) */
#ifndef S_IRUSR
#define S_IRUSR  00400 /* owner read */
#endif
#ifndef S_IWUSR
#define S_IWUSR  00200 /* owner write */
#endif
#ifndef S_IXUSR
#define S_IXUSR  00100 /* owner exec */
#endif

#ifndef S_IRGRP
#define S_IRGRP  00040 /* group read */
#endif
#ifndef S_IWGRP
#define S_IWGRP  00020 /* group write */
#endif
#ifndef S_IXGRP
#define S_IXGRP  00010 /* group exec */
#endif

#ifndef S_IROTH
#define S_IROTH  00004 /* others read */
#endif
#ifndef S_IWOTH
#define S_IWOTH  00002 /* others write */
#endif
#ifndef S_IXOTH
#define S_IXOTH  00001 /* others exec */
#endif

/* utilitaires */
#ifndef S_IRWXU
#define S_IRWXU (S_IRUSR|S_IWUSR|S_IXUsr) /* owner rwx */
#endif
#ifndef S_IRWXG
#define S_IRWXG (S_IRGRP|S_IWGRP|S_IXGRP)
#endif
#ifndef S_IRWXO
#define S_IRWXO (S_IROTH|S_IWOTH|S_IXOTH)
#endif


/* Permissions pour inode_permission */
#define MAY_EXEC    1
#define MAY_WRITE   2
#define MAY_READ    4

int split_path(const char* full_path, char** parent_path, char** filename);
bool inode_permission(inode_t* inode, int mask);

#endif /* _KERNEL_FILE_H */
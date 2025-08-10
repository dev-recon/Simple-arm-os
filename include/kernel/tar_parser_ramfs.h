#ifndef _KERNEL_TAR_PARSER_H
#define _KERNEL_TAR_PARSER_H

#include <kernel/types.h>

/* Structure d'un header TAR (format USTAR) */
typedef struct __attribute__((packed)) {
    char name[100];        /* Nom du fichier */
    char mode[8];          /* Permissions */
    char uid[8];           /* User ID */
    char gid[8];           /* Group ID */
    char size[12];         /* Taille en octal */
    char mtime[12];        /* Modification time */
    char checksum[8];      /* Checksum */
    char typeflag;         /* Type de fichier */
    char linkname[100];    /* Nom du lien */
    char magic[6];         /* "ustar" */
    char version[2];       /* Version "00" */
    char uname[32];        /* Nom utilisateur */
    char gname[32];        /* Nom groupe */
    char devmajor[8];      /* Device major */
    char devminor[8];      /* Device minor */
    char prefix[155];      /* Prefixe du nom */
    char pad[12];          /* Padding */
} tar_header_t;

/* Types de fichiers TAR */
#define TAR_TYPE_FILE        '0'
#define TAR_TYPE_HARDLINK    '1'
#define TAR_TYPE_SYMLINK     '2'
#define TAR_TYPE_CHARDEV     '3'
#define TAR_TYPE_BLOCKDEV    '4'
#define TAR_TYPE_DIRECTORY   '5'
#define TAR_TYPE_FIFO        '6'

/* Signature du fichier binaire cree par qemu_loader_method.sh */
#define USERFS_MAGIC "USERFS01"
#define USERFS_MAGIC_SIZE 8

/* Structures pour construire l'arbre de repertoires */
typedef struct tar_file_entry {
    char name[256];
    uint32_t size;
    uint32_t first_cluster;
    uint8_t attr;
    uint8_t* data;
    struct tar_file_entry* next;
} tar_file_entry_t;

typedef struct tar_dir_entry {
    char name[256];
    char full_path[512];
    uint32_t first_cluster;
    tar_file_entry_t* files;
    struct tar_dir_entry* subdirs;
    struct tar_dir_entry* next;
    struct tar_dir_entry* parent;
} tar_dir_entry_t;


int load_userfs_from_memory(const uint8_t* buffer, uint32_t buffer_size);
#endif

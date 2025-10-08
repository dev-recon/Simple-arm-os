#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/mash.h"

// Table des commandes enregistrées
#define MAX_COMMANDS 32
static command_entry_t command_table[MAX_COMMANDS];
static int command_count = 0;

// Fonctions de commandes (déclarations)
static int cmd_help(int argc, char* argv[]);
static int cmd_echo(int argc, char* argv[]);
static int cmd_touch(int argc, char* argv[]);
static int cmd_rm(int argc, char* argv[]);
static int cmd_write(int argc, char* argv[]);
static int cmd_clear(int argc, char* argv[]);
static int cmd_info(int argc, char* argv[]);
static int cmd_storage(int argc, char* argv[]);
static int cmd_save(int argc, char* argv[]);
static int cmd_load(int argc, char* argv[]);
static int cmd_ps(int argc, char* argv[]);
static int cmd_yield(int argc, char* argv[]);
static int cmd_fork_test(int argc, char* argv[]);
static int cmd_pstree(int argc, char* argv[]);
static int cmd_pwd(int argc, char* argv[]);
static int cmd_ls(int argc, char *argv[]);
static int cmd_cat(int argc, char *argv[]);
static int cmd_cd(int argc, char *argv[]);

int register_command(const char* name, const char* desc, command_func_t function);

// Initialiser le système de processus
int command_init(void) {
    
    // Initialiser la table des commandes
    for (int i = 0; i < MAX_COMMANDS; i++) {
        command_table[i].name = NULL;
        command_table[i].function = NULL;
    }
    command_count = 0;
    
    // Enregistrer les commandes de base (sauf ls et cat qui sont maintenant des exécutables)
    register_command("help", "Afficher cette aide", cmd_help);
    register_command("echo", "Afficher du texte", cmd_echo);
    register_command("touch", "Creer un fichier vide", cmd_touch);
    register_command("rm", "Supprimer un fichier", cmd_rm);
    register_command("write", "Ecrire dans un fichier", cmd_write);
    register_command("clear", "Effacer l'ecran", cmd_clear);
    register_command("info", "Informations systeme", cmd_info);
    register_command("storage", "Gestion du stockage", cmd_storage);
    register_command("save", "Sauvegarder le FS", cmd_save);
    register_command("load", "Charger le FS", cmd_load);
    register_command("ps", "Lister les taches", cmd_ps);
    register_command("yield", "Ceder le CPU", cmd_yield);
    register_command("fork", "Tester fork()", cmd_fork_test);
    register_command("yield", "Ceder le CPU", cmd_yield);
    register_command("pwd", "Afficher le répertoire courant", cmd_pwd);
    register_command("ls", "Lister fichier ou répertoire", cmd_ls);
    register_command("cat", "lire le contenu d'un fichier", cmd_cat);
    register_command("cd", "Changer le répertoire courant", cmd_cd);

    return SHELL_OK;
}


// Enregistrer une commande
int register_command(const char* name, const char* desc, 
                                        command_func_t function) {
    if (command_count >= MAX_COMMANDS) {
        return -SHELL_MAX_ARGS;
    }
    
    command_table[command_count].name = name;
    command_table[command_count].description = desc;
    command_table[command_count].function = function;
    command_count++;
    
    return SHELL_OK;
}

// Trouver une commande
command_entry_t* find_command(const char* name) {
    for (int i = 0; i < command_count; i++) {
        if (command_table[i].name && strcmp(command_table[i].name, name) == 0) {
            return &command_table[i];
        }
    }
    return NULL;
}

// Lister les commandes
void list_commands(void) {
    printf("Commandes disponibles:\n");
    printf("======================\n");
    
    for (int i = 0; i < command_count; i++) {
        if (command_table[i].name) {
            printf("  %s",command_table[i].name);
            
            // Padding pour l'alignement
            int len = strlen(command_table[i].name);
            for (int j = len; j < 10; j++) {
                printf(" ");
            }
            
            printf("- %s\n",command_table[i].description);
        }
    }
}

#define BUF_SIZE 4096

static int cmd_cd(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cd <répertoire>\n");
        return 1;
    }

    return chdir(argv[1]);

}

static int cmd_cat(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cat <fichier>\n");
        return 1;
    }

    int fd = open(argv[1], O_RDONLY , 0);
    if(fd) {
        struct stat st;
        fstat(fd, &st);
        char car = 0;
        int i = 0;
        char *buffer = malloc(st.st_size+1);
        read(fd, buffer, st.st_size);
        while( i < st.st_size)
            putc_tty(buffer[i++]);
        close(fd);
        free(buffer);
    } else {
        printf("Erreur: %d\n", fd);
        return fd;
    }
    
    return 0;
}


static int cmd_ls(int argc, char *argv[]) {

    const char *path = (argc > 1) ? argv[1] : ".";
    int fd;

    char *buf = malloc(BUF_SIZE);
    ssize_t n;
    
    /* Ouvrir le répertoire */
    fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        //perror(path);
        free(buf);
        return 1;
    }
    
    /* Lire les entrées avec sys_getdents */
    while ((n = getdents(fd, buf, BUF_SIZE)) > 0) {
        char *ptr = buf;
        
        while (ptr < buf + n) {
            /* Format dépend de votre sys_getdents */
            /* Structure typique : */
            struct {
                uint32_t d_ino;
                uint32_t d_off;
                uint16_t d_reclen;
                uint8_t  d_type;
                char     d_name[];
            } *entry = (void*)ptr;
            
            /* Ignorer . et .. */
            if (strcmp(entry->d_name, ".") != 0 && 
                strcmp(entry->d_name, "..") != 0 &&
                entry->d_ino != 0 ) {

                /* Colorier les répertoires */
                if (entry->d_type == 4) {  /* DT_DIR */
                    printf("\033[1;34m%s\033[0m\n", entry->d_name);
                } else {
                    printf("%s\n", entry->d_name);
                }
            }
            
            ptr += entry->d_reclen;
        }
    }
    
    if (n < 0) {
        //perror("getdents");
        close(fd);
        free(buf);
        return 1;
    }
    
    close(fd);
    free(buf);
    return 0;
}

// === Implémentations des commandes ===
static int cmd_pwd(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("%s\n", getcwd(NULL, 0));
    return 0;
}

static int cmd_help(int argc, char* argv[]) {
    (void)argc; (void)argv;
    list_commands();
    return 0;
}

static int cmd_echo(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        printf(argv[i]);
        if (i < argc - 1) {
            printf(" ");
        }
    }
    printf("\n");
    return 0;
}

static int cmd_touch(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: touch <fichier>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_CREAT | O_RDWR, 0);
    if(fd) {
        printf("Fichier %s cree\n",argv[1]);
        close(fd);
    } else {
        printf("Erreur: %d\n", fd);
        return fd;
    }
    
    return 0;
}

static int cmd_rm(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: rm <fichier>\n");
        return 1;
    }
    
    int result = unlink(argv[1]);
    if (result == 0) {
        printf("Fichier %s supprime\n",argv[1]);
    } else {
        printf("Erreur: %d\n", result);
        return result;
    }
    
    return 0;
}

static int cmd_write(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: write <fichier> <texte...>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_APPEND , 0);
    if(!fd)
        fd = open(argv[1], O_CREAT  , 0);
    if (fd < 0) {
        printf("Erreur: impossible d'ouvrir %s\n",argv[1]);
        return 1;
    }
    
    // Écrire tous les arguments à partir du 2ème
    for (int i = 2; i < argc; i++) {
        write(fd, argv[i], strlen(argv[i]));
        if (i < argc - 1) {
            write(fd, " ", 1);
        }
    }
    write(fd, "\n", 1);
    
    close(fd);
    printf("Texte ecrit dans %s\n", argv[1]);
    
    return 0;
}

static int cmd_clear(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("\033[2J\033[H");
    return 0;
}

static int cmd_info(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_storage(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_save(int argc, char* argv[]) {
    (void)argc; (void)argv;
    
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_load(int argc, char* argv[]) {
    (void)argc; (void)argv;
    
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_ps(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_yield(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_fork_test(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}

static int cmd_pstree(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("Not yet implemented\n");
    return 0;
}
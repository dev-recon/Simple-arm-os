#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include "../include/mash.h"

// Table of registered commands
#define MAX_COMMANDS 32
static command_entry_t command_table[MAX_COMMANDS];
static int command_count = 0;

// Command functions (declarations)
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
static int cmd_sleep(int argc, char *argv[]);

int register_command(const char* name, const char* desc, command_func_t function);

// Initialize the command system
int command_init(void) {

    // Initialize the command table
    for (int i = 0; i < MAX_COMMANDS; i++) {
        command_table[i].name = NULL;
        command_table[i].function = NULL;
    }
    command_count = 0;
    
    // Register basic commands (except ls and cat which are now executables)
    register_command("help", "Display this help", cmd_help);
    register_command("echo", "Display text", cmd_echo);
    register_command("touch", "Create an empty file", cmd_touch);
    register_command("rm", "Delete a file", cmd_rm);
    register_command("write", "Write to a file", cmd_write);
    register_command("clear", "Clear the screen", cmd_clear);
    register_command("info", "Display system information", cmd_info);
    register_command("storage", "Manage storage", cmd_storage);
    register_command("save", "Save the FS", cmd_save);
    register_command("load", "Load the FS", cmd_load);
    register_command("ps", "List tasks", cmd_ps);
    register_command("yield", "Yield the CPU", cmd_yield);
    register_command("fork", "Test fork()", cmd_fork_test);
    register_command("yield", "Yield the CPU", cmd_yield);
    register_command("pwd", "Display current directory", cmd_pwd);
    register_command("ls", "List files or directories", cmd_ls);
    register_command("cat", "Read the contents of a file", cmd_cat);
    register_command("cd", "Change the current directory", cmd_cd);
    register_command("sleep", "Sleep for a specified time", cmd_sleep);

    return SHELL_OK;
}


// Register a command
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

// Find a command
command_entry_t* find_command(const char* name) {
    for (int i = 0; i < command_count; i++) {
        if (command_table[i].name && strcmp(command_table[i].name, name) == 0) {
            return &command_table[i];
        }
    }
    return NULL;
}

// List available commands
void list_commands(void) {
    printf("Available commands:\n");
    printf("======================\n");
    
    for (int i = 0; i < command_count; i++) {
        if (command_table[i].name) {
            printf("  %s",command_table[i].name);

            // Padding for alignment
            int len = strlen(command_table[i].name);
            for (int j = len; j < 10; j++) {
                printf(" ");
            }
            
            printf("- %s\n",command_table[i].description);
        }
    }
}

#define BUF_SIZE 4096
// === Implementation of commands ===

static int cmd_sleep(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: sleep <seconds>\n");
        return 1;
    }

    unsigned int seconds = atoi(argv[1]);

    printf("Sleeping for %u seconds...\n", seconds);
    sleep(seconds);
    printf("Awake!\n");
    return 0;
}

static int cmd_cd(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cd <directory>\n");
        return 1;
    }

    return chdir(argv[1]);

}

static int cmd_cat(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cat <file>\n");
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
        printf("Error: %d\n", fd);
        return fd;
    }
    
    return 0;
}

// Simple implementation of 'ls' command using getdents syscall
static int cmd_ls(int argc, char *argv[]) {

    const char *path = (argc > 1) ? argv[1] : ".";
    int fd;

    char *buf = malloc(BUF_SIZE);
    ssize_t n;

    /* Open directory */
    fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        //perror(path);
        free(buf);
        return 1;
    }

    /* Read directory entries with sys_getdents */
    while ((n = getdents(fd, buf, BUF_SIZE)) > 0) {
        char *ptr = buf;
        
        while (ptr < buf + n) {
            struct {
                uint32_t d_ino;
                uint32_t d_off;
                uint16_t d_reclen;
                uint8_t  d_type;
                char     d_name[];
            } *entry = (void*)ptr;
            
            /* Ignore . and .. */
            if (strcmp(entry->d_name, ".") != 0 && 
                strcmp(entry->d_name, "..") != 0 &&
                entry->d_ino != 0 ) {

                /* Color directories */
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

// === Implementation of commands ===
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
        printf("Usage: touch <file>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_CREAT | O_RDWR, 0);
    if(fd) {
        printf("File %s created\n",argv[1]);
        close(fd);
    } else {
        printf("Erreur: %d\n", fd);
        return fd;
    }
    
    return 0;
}

static int cmd_rm(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: rm <file>\n");
        return 1;
    }

    int result = 0;

    int fd = open(argv[1], O_RDONLY,0);
    if (fd >= 0) {
        close(fd);
        printf("File exists, now unlinking...\n");

        /* Remove the file */
        if ((result = unlink(argv[1])) == 0)
            printf("File removed successfully\n");
        
    } else {
        printf("Error: %d\n", result);
    }

    return result;
}

static int cmd_write(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: write <file> <text...>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_APPEND | O_WRONLY , 0);
    if(!fd) {
        printf("File %s does not exist, creating it...\n",argv[1]);
    }

    fd = open(argv[1], O_CREAT | O_WRONLY  , 0);
    if (fd < 0) {
        printf("Error: cannot open %s\n",argv[1]);
        return 1;
    }
    
    // Write all arguments starting from the 2nd
    for (int i = 2; i < argc; i++) {
        write(fd, argv[i], strlen(argv[i]));
        if (i < argc - 1) {
            write(fd, " ", 1);
        }
    }
    write(fd, "\n", 1);
    
    close(fd);
    printf("Text written to %s\n", argv[1]);
    
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
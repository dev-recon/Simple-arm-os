#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include "../include/mash.h"

// Table of registered commands
#define MAX_COMMANDS 32
static command_entry_t command_table[MAX_COMMANDS];
static int command_count = 0;

// Command functions (declarations)
static int cmd_help(int argc, char* argv[]);
static int cmd_clear(int argc, char* argv[]);
static int cmd_info(int argc, char* argv[]);
static int cmd_storage(int argc, char* argv[]);
static int cmd_save(int argc, char* argv[]);
static int cmd_load(int argc, char* argv[]);
static int cmd_yield(int argc, char* argv[]);
static int cmd_fork_test(int argc, char* argv[]);
static int cmd_pstree(int argc, char* argv[]);
static int cmd_cd(int argc, char *argv[]);

int register_command(const char* name, const char* desc, command_func_t function);

// Initialize the command system
int command_init(void) {

    // Initialize the command table
    for (int i = 0; i < MAX_COMMANDS; i++) {
        command_table[i].name = NULL;
        command_table[i].function = NULL;
    }
    command_count = 0;
    
    // Register builtins; simple stateless commands live in /bin.
    register_command("help", "Display this help", cmd_help);
    register_command("clear", "Clear the screen", cmd_clear);
    register_command("info", "Display system information", cmd_info);
    register_command("storage", "Manage storage", cmd_storage);
    register_command("save", "Save the FS", cmd_save);
    register_command("load", "Load the FS", cmd_load);
    register_command("yield", "Yield the CPU", cmd_yield);
    register_command("fork", "Test fork()", cmd_fork_test);
    register_command("cd", "Change the current directory", cmd_cd);

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

static int cmd_cd(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cd <directory>\n");
        return 1;
    }

    return chdir(argv[1]);

}


static int cmd_help(int argc, char* argv[]) {
    (void)argc; (void)argv;
    list_commands();
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

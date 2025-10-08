#ifndef _MASH_H
#define _MASH_H

// Signatures des fonctions de commandes
typedef int (*command_func_t)(int argc, char* argv[]);

// Structure pour enregistrer les commandes
typedef struct {
    const char* name;
    const char* description;
    command_func_t function;
} command_entry_t;


#define SHELL_BUFFER_SIZE 256
#define SHELL_MAX_ARGS      16

// Codes de retour des commandes
#define SHELL_OK            0
#define SHELL_ERROR         1
#define SHELL_EXIT          2

static char input_buffer[SHELL_BUFFER_SIZE];
static char* argv_buffer[SHELL_MAX_ARGS];
static int shell_running = 0;

#endif
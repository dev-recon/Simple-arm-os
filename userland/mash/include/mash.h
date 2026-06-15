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

int register_command(const char* name, const char* desc, command_func_t function);
command_entry_t* find_command(const char* name);
void list_commands(void);
int command_init(void);
int command_count_registered(void);
const char* command_name_at(int index);
const char* shell_getenv(const char* name);
void shell_print_prompt(void);
char* shell_read_line(void);
void shell_line_edit_init(void);

#define SHELL_BUFFER_SIZE 256
#define SHELL_MAX_ARGS      16

// Codes de retour des commandes
#define SHELL_OK            0
#define SHELL_ERROR         1
#define SHELL_EXIT          2

extern char input_buffer[SHELL_BUFFER_SIZE];
extern char* argv_buffer[SHELL_MAX_ARGS];
extern int shell_running;

#endif

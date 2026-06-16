#ifndef _MASH_H
#define _MASH_H

#include <stdio.h>
#include <unistd.h>

static inline int putc_tty(char c) {
    return write(1, &c, 1);
}

static inline int getc_tty(void) {
    char c;
    return read(0, &c, 1) == 1 ? (unsigned char)c : -1;
}

static inline void pflush(void) {
    fflush(stdout);
}

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
int shell_setenv(const char* name, const char* value);
int shell_unsetenv(const char* name);
int shell_env_count_registered(void);
const char* shell_env_name_at(int index);
const char* shell_env_value_at(int index);
int shell_last_status(void);
int shell_execute_line(char* line);
int shell_source_file(const char* path, int argc, char* argv[]);
int shell_push_script_args(const char* name, int argc, char* argv[]);
void shell_pop_script_args(void);
void shell_print_prompt(void);
char* shell_read_line(void);
void shell_line_edit_init(void);

#define SHELL_BUFFER_SIZE 256
#define SHELL_MAX_ARGS      16

// Codes de retour des commandes
#define SHELL_OK            0
#define SHELL_ERROR         1
#define SHELL_EXIT          (-1000)

extern char input_buffer[SHELL_BUFFER_SIZE];
extern char* argv_buffer[SHELL_MAX_ARGS];
extern int shell_running;

#endif

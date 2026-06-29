/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/mash/src/command.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

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
#include <errno.h>
#include "arm_os_abi.h"
#include "../include/mash.h"
#include "../include/jobs.h"

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
static int cmd_cd(int argc, char *argv[]);
static int cmd_export(int argc, char* argv[]);
static int cmd_env(int argc, char* argv[]);
static int cmd_unset(int argc, char* argv[]);
static int cmd_set(int argc, char* argv[]);
static int cmd_source(int argc, char* argv[]);
static int cmd_test(int argc, char* argv[]);

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
    register_command("export", "Set or print shell environment", cmd_export);
    register_command("env", "Print shell environment", cmd_env);
    register_command("unset", "Remove shell environment variables", cmd_unset);
    register_command("set", "Print or set shell variables", cmd_set);
    register_command("source", "Execute commands from a file", cmd_source);
    register_command(".", "Execute commands from a file", cmd_source);
    register_command("test", "Evaluate simple file tests", cmd_test);
    register_command("[", "Evaluate simple file tests", cmd_test);
    register_command("jobs", "List background jobs", jobs_builtin);
    register_command("fg", "Bring a background job to the foreground", jobs_fg_builtin);
    register_command("bg", "Resume a background job", jobs_bg_builtin);
    register_command("wait", "Wait for background jobs", jobs_wait_builtin);

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

int command_count_registered(void) {
    return command_count;
}

const char* command_name_at(int index) {
    if (index < 0 || index >= command_count)
        return NULL;
    return command_table[index].name;
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
    const char* target;
    char oldpwd[256];
    char newpwd[256];

    if (argc < 2) {
        target = shell_getenv("HOME");
        if (!target || !*target)
            target = "/";
    } else if (strcmp(argv[1], "-") == 0) {
        target = shell_getenv("OLDPWD");
        if (!target || !*target) {
            printf("cd: OLDPWD not set\n");
            return 1;
        }
        printf("%s\n", target);
    } else {
        target = argv[1];
    }

    if (!getcwd(oldpwd, sizeof(oldpwd)))
        oldpwd[0] = '\0';

    if (chdir(target) < 0) {
        printf("cd: %s: %s\n", target, strerror(errno));
        return 1;
    }

    if (getcwd(newpwd, sizeof(newpwd))) {
        if (oldpwd[0])
            shell_setenv("OLDPWD", oldpwd);
        shell_setenv("PWD", newpwd);
    }

    return 0;

}

static int shell_name_start(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_';
}

static int shell_name_char(char c) {
    return shell_name_start(c) || (c >= '0' && c <= '9');
}

static int command_valid_env_name(const char* name) {
    if (!name || !shell_name_start(*name))
        return 0;

    name++;
    while (*name) {
        if (!shell_name_char(*name))
            return 0;
        name++;
    }

    return 1;
}

static int cmd_export(int argc, char* argv[]) {
    int i;

    if (argc == 1)
        return cmd_env(argc, argv);

    for (i = 1; i < argc; i++) {
        char* eq = strchr(argv[i], '=');

        if (eq) {
            *eq = '\0';
            if (!command_valid_env_name(argv[i])) {
                printf("export: invalid name '%s'\n", argv[i]);
                *eq = '=';
                return 1;
            }
            if (shell_setenv(argv[i], eq + 1) < 0) {
                printf("export: environment is full\n");
                *eq = '=';
                return 1;
            }
            *eq = '=';
        } else {
            if (!command_valid_env_name(argv[i])) {
                printf("export: invalid name '%s'\n", argv[i]);
                return 1;
            }
            if (!shell_getenv(argv[i]) && shell_setenv(argv[i], "") < 0) {
                printf("export: environment is full\n");
                return 1;
            }
        }
    }

    return 0;
}

static int cmd_env(int argc, char* argv[]) {
    int i;

    (void)argc;
    (void)argv;

    for (i = 0; i < shell_env_count_registered(); i++) {
        const char* name = shell_env_name_at(i);
        const char* value = shell_env_value_at(i);

        if (name)
            printf("%s=%s\n", name, value ? value : "");
    }

    return 0;
}

static int cmd_unset(int argc, char* argv[]) {
    int i;

    for (i = 1; i < argc; i++)
        shell_unsetenv(argv[i]);

    return 0;
}

static int cmd_set(int argc, char* argv[]) {
    int status = 0;

    if (argc == 1)
        return cmd_env(argc, argv);

    for (int i = 1; i < argc; i++) {
        char* eq = strchr(argv[i], '=');
        if (!eq) {
            printf("set: expected NAME=VALUE, got '%s'\n", argv[i]);
            status = 1;
            continue;
        }

        *eq = '\0';
        if (!command_valid_env_name(argv[i]) || shell_setenv(argv[i], eq + 1) < 0) {
            printf("set: cannot set '%s'\n", argv[i]);
            status = 1;
        }
        *eq = '=';
    }

    return status;
}

static int test_path(const char* op, const char* path)
{
    struct stat st;
    int ret;

    if (strcmp(op, "-e") == 0)
        return lstat(path, &st) == 0 ? 0 : 1;

    ret = stat(path, &st);
    if (ret < 0)
        return 1;

    if (strcmp(op, "-f") == 0)
        return S_ISREG(st.st_mode) ? 0 : 1;
    if (strcmp(op, "-d") == 0)
        return S_ISDIR(st.st_mode) ? 0 : 1;
    if (strcmp(op, "-x") == 0)
        return (st.st_mode & 0111) ? 0 : 1;
    if (strcmp(op, "-r") == 0)
        return (st.st_mode & 0444) ? 0 : 1;
    if (strcmp(op, "-w") == 0)
        return (st.st_mode & 0222) ? 0 : 1;

    return -1;
}

static int parse_int(const char* s, int* out)
{
    int sign = 1;
    int value = 0;

    if (!s || !*s || !out)
        return -1;
    if (*s == '-') {
        sign = -1;
        s++;
    }
    if (!*s)
        return -1;
    while (*s) {
        if (*s < '0' || *s > '9')
            return -1;
        value = value * 10 + (*s - '0');
        s++;
    }
    *out = sign * value;
    return 0;
}

static int cmd_test(int argc, char* argv[]) {
    int bracket = argc > 0 && strcmp(argv[0], "[") == 0;
    int a;
    int b;

    if (bracket) {
        if (argc < 2 || strcmp(argv[argc - 1], "]") != 0) {
            printf("[: missing ']'\n");
            return 2;
        }
        argc--;
    }

    if (argc == 1)
        return 1;

    if (argc == 2)
        return argv[1][0] ? 0 : 1;

    if (argc == 3 && argv[1][0] == '-') {
        int ret = test_path(argv[1], argv[2]);
        if (ret >= 0)
            return ret;
    }

    if (argc == 4) {
        if (strcmp(argv[2], "=") == 0)
            return strcmp(argv[1], argv[3]) == 0 ? 0 : 1;
        if (strcmp(argv[2], "!=") == 0)
            return strcmp(argv[1], argv[3]) != 0 ? 0 : 1;
        if (strcmp(argv[2], "-eq") == 0 ||
            strcmp(argv[2], "-ne") == 0) {
            if (parse_int(argv[1], &a) < 0 || parse_int(argv[3], &b) < 0)
                return 2;
            if (strcmp(argv[2], "-eq") == 0)
                return a == b ? 0 : 1;
            return a != b ? 0 : 1;
        }
    }

    printf("Usage: test EXPR\n");
    return 2;
}

static int source_is_word_char(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '_';
}

static int source_word_is(const char* start, int len, const char* word) {
    int i;

    for (i = 0; i < len && word[i]; i++) {
        if (start[i] != word[i])
            return 0;
    }

    return i == len && word[i] == '\0';
}

static int source_if_depth_delta(const char* line) {
    int delta = 0;
    char quote = 0;
    const char* p = line;

    while (*p) {
        if (quote) {
            if (*p == quote)
                quote = 0;
            p++;
            continue;
        }

        if (*p == '\'' || *p == '"') {
            quote = *p++;
            continue;
        }

        if (*p == '#')
            break;

        if (source_is_word_char(*p)) {
            const char* start = p;
            int len = 0;

            while (source_is_word_char(*p)) {
                len++;
                p++;
            }

            if (source_word_is(start, len, "if") ||
                source_word_is(start, len, "for"))
                delta++;
            else if (source_word_is(start, len, "fi") ||
                     source_word_is(start, len, "done"))
                delta--;
            continue;
        }

        p++;
    }

    return delta;
}

static int source_append_line(char* block, int* block_len, const char* line) {
    int len = strlen(line);

    if (*block_len + len + 3 >= SHELL_BUFFER_SIZE)
        return -1;

    memcpy(block + *block_len, line, len);
    *block_len += len;
    block[(*block_len)++] = ';';
    block[(*block_len)++] = ' ';
    block[*block_len] = '\0';
    return 0;
}

int shell_source_file(const char* path, int argc, char* argv[]) {
    char buffer[512];
    char line[SHELL_BUFFER_SIZE];
    char block[SHELL_BUFFER_SIZE];
    int fd;
    int n;
    int line_len = 0;
    int block_len = 0;
    int if_depth = 0;
    int status = 0;
    int i;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        printf("source: cannot open %s\n", path);
        return 1;
    }

    if (shell_push_script_args(path, argc, argv) < 0) {
        printf("source: script nesting too deep\n");
        close(fd);
        return 1;
    }

    block[0] = '\0';

    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        for (i = 0; i < n; i++) {
            if (buffer[i] == '\r')
                continue;

            if (buffer[i] == '\n') {
                line[line_len] = '\0';
                if (if_depth > 0 || source_if_depth_delta(line) > 0) {
                    if (source_append_line(block, &block_len, line) < 0) {
                        printf("source: block too long\n");
                        close(fd);
                        shell_pop_script_args();
                        return 1;
                    }
                    if_depth += source_if_depth_delta(line);
                    if (if_depth <= 0) {
                        status = shell_execute_line(block);
                        if (status == SHELL_EXIT) {
                            close(fd);
                            shell_pop_script_args();
                            return status;
                        }
                        block_len = 0;
                        block[0] = '\0';
                        if_depth = 0;
                    }
                } else {
                    status = shell_execute_line(line);
                    if (status == SHELL_EXIT) {
                        close(fd);
                        shell_pop_script_args();
                        return status;
                    }
                }
                line_len = 0;
                continue;
            }

            if (line_len >= SHELL_BUFFER_SIZE - 1) {
                printf("source: line too long\n");
                close(fd);
                shell_pop_script_args();
                return 1;
            }
            line[line_len++] = buffer[i];
        }
    }

    if (line_len > 0) {
        line[line_len] = '\0';
        if (if_depth > 0 || source_if_depth_delta(line) > 0) {
            if (source_append_line(block, &block_len, line) < 0) {
                printf("source: block too long\n");
                close(fd);
                shell_pop_script_args();
                return 1;
            }
            if_depth += source_if_depth_delta(line);
        } else {
            status = shell_execute_line(line);
        }
    }

    if (if_depth > 0) {
        printf("source: missing fi/done\n");
        close(fd);
        shell_pop_script_args();
        return 1;
    }

    if (block_len > 0) {
        status = shell_execute_line(block);
    }

    close(fd);
    shell_pop_script_args();
    return status;
}

static int cmd_source(int argc, char* argv[]) {
    if (argc < 2) {
        printf("%s: missing file operand\n", argv[0]);
        return 1;
    }

    return shell_source_file(argv[1], argc - 2, &argv[2]);
}


static int cmd_help(int argc, char* argv[]) {
    (void)argc; (void)argv;
    list_commands();
    return 0;
}

static int cmd_clear(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("\033[H\033[2J\033[3J");
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

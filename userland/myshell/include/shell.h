/* include/shell.h */
#ifndef _SHELL_H
#define _SHELL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <termios.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <ctype.h>

#define MAX_LINE 1024
#define MAX_ARGS 64
#define MAX_JOBS 32
#define MAX_HISTORY 100
#define MAX_PATH 256

/* Types de tokens */
typedef enum {
    TOKEN_WORD,
    TOKEN_PIPE,
    TOKEN_REDIRECT_IN,
    TOKEN_REDIRECT_OUT,
    TOKEN_REDIRECT_APPEND,
    TOKEN_REDIRECT_ERR,
    TOKEN_BACKGROUND,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_SEMICOLON,
    TOKEN_EOF
} token_type_t;

/* Token */
typedef struct token {
    token_type_t type;
    char* value;
    struct token* next;
} token_t;

/* Redirection */
typedef struct redirect {
    int fd;
    char* filename;
    token_type_t type;
    struct redirect* next;
} redirect_t;

/* Commande simple */
typedef struct simple_cmd {
    char** args;
    int argc;
    redirect_t* redirects;
} simple_cmd_t;

/* Pipeline */
typedef struct pipeline {
    simple_cmd_t** commands;
    int cmd_count;
    int background;
} pipeline_t;

/* Command line complete */
typedef struct command_line {
    pipeline_t** pipelines;
    int pipeline_count;
    token_type_t separators[MAX_ARGS];
} command_line_t;

/* Job */
typedef struct job {
    int id;
    pid_t pgid;
    char* command;
    int running;
    int background;
    pid_t* pids;
    int pid_count;
} job_t;

/* Variables locales du shell */
typedef struct shell_var {
    char* name;
    char* value;
    struct shell_var* next;
} shell_var_t;

/* Shell state */
typedef struct shell_state {
    char* prompt;
    char* cwd;
    int last_exit_status;
    int interactive;
    char** history;
    int history_count;
    int history_index;
    struct termios original_termios;
    job_t jobs[MAX_JOBS];
    int job_count;
    shell_var_t* variables;
} shell_state_t;

extern shell_state_t shell_state;

/* Fonctions principales - main.c */
void shell_init(int argc, char** argv);
void shell_cleanup(void);
void shell_loop(void);
char* read_line(void);

/* Parser - parser.c */
token_t* tokenize(const char* line);
command_line_t* parse_command_line(token_t* tokens);
pipeline_t* parse_pipeline(token_t** tokens);
simple_cmd_t* parse_simple_command(token_t** tokens);
void free_tokens(token_t* tokens);
void free_command_line(command_line_t* cmdline);
void free_pipeline(pipeline_t* pipeline);
void free_simple_command(simple_cmd_t* cmd);

/* Executor - executor.c */
void execute_command_line(command_line_t* cmdline);
int execute_pipeline(pipeline_t* pipeline);
int execute_simple_command(simple_cmd_t* cmd, int background);
int execute_pipe_sequence(pipeline_t* pipeline);
void apply_redirections(redirect_t* redirects);

/* Builtins - builtins.c */
int execute_builtin(const char* cmd, int argc, char** argv);
int builtin_cd(int argc, char** argv);
int builtin_pwd(int argc, char** argv);
int builtin_echo(int argc, char** argv);
int builtin_exit(int argc, char** argv);
int builtin_export(int argc, char** argv);
int builtin_unset(int argc, char** argv);
int builtin_env(int argc, char** argv);
int builtin_history(int argc, char** argv);
int builtin_jobs(int argc, char** argv);
int builtin_fg(int argc, char** argv);
int builtin_bg(int argc, char** argv);
int builtin_help(int argc, char** argv);
int builtin_test(int argc, char** argv);
int builtin_true(int argc, char** argv);
int builtin_false(int argc, char** argv);
int builtin_source(int argc, char** argv);

/* Variables - variables.c */
void init_shell_variables(int argc, char** argv);
char* expand_variables(const char* str);
void set_shell_variable(const char* name, const char* value);
char* get_shell_variable(const char* name);
void unset_shell_variable(const char* name);
char* expand_tilde(const char* str);

/* History - history.c */
void add_to_history(const char* line);
void save_history(const char* filename);
void load_history(const char* filename);
char* get_history_line(int index);

/* Jobs - jobs.c */
void init_job_control(void);
void add_job(pid_t pgid, const char* command, int background, pid_t* pids, int pid_count);
void remove_job(int job_id);
void update_job_status(void);
job_t* find_job(int job_id);
void cleanup_jobs(void);

/* Signal handlers - signals.c */
void setup_signal_handlers(void);
void sigchld_handler(int sig);
void sigint_handler(int sig);
void sigtstp_handler(int sig);

/* RC files - rcfiles.c */
void load_rc_files(void);
void execute_rc_file(const char* filename);

/* Prompt - prompt.c */
void update_prompt(void);
char* expand_prompt(const char* ps1);

#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>
#include "../include/mash.h"
#include "../include/jobs.h"

#ifndef SA_RESTART
#define SA_RESTART 0x01
#endif

char input_buffer[SHELL_BUFFER_SIZE];
char* argv_buffer[SHELL_MAX_ARGS];
int shell_running = 0;

static char token_buffer[SHELL_BUFFER_SIZE];
static int shell_status = 0;

#define SHELL_SCRIPT_ARG_MAX 10
#define SHELL_SCRIPT_STACK_MAX 4

typedef struct shell_script_frame {
    const char* name;
    int argc;
    const char* argv[SHELL_SCRIPT_ARG_MAX];
} shell_script_frame_t;

static shell_script_frame_t script_frames[SHELL_SCRIPT_STACK_MAX];
static int script_frame_depth = 1;

static int shell_is_login_shell(void)
{
    /*
     * The boot shell is created directly by init. Letting it exit leaves the
     * system without an interactive user session, so only child/nested shells
     * are allowed to terminate via the exit builtin.
     */
    return getppid() == 1;
}

#define SHELL_MAX_ENV       16
#define SHELL_ENV_NAME_LEN  32
#define SHELL_ENV_VALUE_LEN 160
typedef struct shell_env {
    char name[SHELL_ENV_NAME_LEN];
    char value[SHELL_ENV_VALUE_LEN];
} shell_env_t;

static shell_env_t shell_env[SHELL_MAX_ENV];
static int shell_env_count = 0;
static char shell_env_strings[SHELL_MAX_ENV][SHELL_ENV_NAME_LEN + SHELL_ENV_VALUE_LEN + 1];
static char* shell_envp[SHELL_MAX_ENV + 1];
static int shell_pgid = 0;

static void shell_sigchld_handler(int sig)
{
    (void)sig;
}

static void shell_set_foreground_pgid(int pgid) {
    if (pgid >= 0)
        tcsetpgrp(STDIN_FILENO, pgid);
}

static void shell_restore_foreground(void) {
    shell_set_foreground_pgid(shell_pgid);
}

typedef struct shell_redirs {
    const char* input;
    const char* output;
    const char* error;
    int output_append;
    int error_append;
} shell_redirs_t;

#define SHELL_MAX_PIPELINE 8

typedef struct shell_command {
    int argc;
    char** argv;
    shell_redirs_t redirs;
} shell_command_t;

static int token_is_special(char c) {
    return c == '<' || c == '>' || c == '&' || c == '|' || c == ';';
}

static int token_has_slash(const char* s) {
    while (*s) {
        if (*s == '/')
            return 1;
        s++;
    }
    return 0;
}

static const char* shell_last_char(const char* s, char c);

static int shell_var_start(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_';
}

static int shell_var_char(char c) {
    return shell_var_start(c) || (c >= '0' && c <= '9');
}

const char* shell_getenv(const char* name) {
    int i;

    for (i = 0; i < shell_env_count; i++) {
        if (strcmp(shell_env[i].name, name) == 0)
            return shell_env[i].value;
    }

    return NULL;
}

int shell_setenv(const char* name, const char* value) {
    int i;

    if (!name || !value || !*name)
        return -1;

    for (i = 0; i < shell_env_count; i++) {
        if (strcmp(shell_env[i].name, name) == 0) {
            strncpy(shell_env[i].value, value, SHELL_ENV_VALUE_LEN - 1);
            shell_env[i].value[SHELL_ENV_VALUE_LEN - 1] = '\0';
            return 0;
        }
    }

    if (shell_env_count >= SHELL_MAX_ENV)
        return -1;

    strncpy(shell_env[shell_env_count].name, name, SHELL_ENV_NAME_LEN - 1);
    shell_env[shell_env_count].name[SHELL_ENV_NAME_LEN - 1] = '\0';
    strncpy(shell_env[shell_env_count].value, value, SHELL_ENV_VALUE_LEN - 1);
    shell_env[shell_env_count].value[SHELL_ENV_VALUE_LEN - 1] = '\0';
    shell_env_count++;
    return 0;
}

int shell_unsetenv(const char* name) {
    int i;

    if (!name || !*name)
        return -1;

    for (i = 0; i < shell_env_count; i++) {
        if (strcmp(shell_env[i].name, name) == 0) {
            int j;

            for (j = i; j < shell_env_count - 1; j++)
                shell_env[j] = shell_env[j + 1];
            shell_env_count--;
            return 0;
        }
    }

    return 0;
}

int shell_env_count_registered(void) {
    return shell_env_count;
}

const char* shell_env_name_at(int index) {
    if (index < 0 || index >= shell_env_count)
        return NULL;
    return shell_env[index].name;
}

const char* shell_env_value_at(int index) {
    if (index < 0 || index >= shell_env_count)
        return NULL;
    return shell_env[index].value;
}

int shell_last_status(void) {
    return shell_status;
}

int shell_push_script_args(const char* name, int argc, char* argv[]) {
    int i;
    shell_script_frame_t* frame;

    if (script_frame_depth >= SHELL_SCRIPT_STACK_MAX)
        return -1;

    frame = &script_frames[script_frame_depth++];
    frame->name = name ? name : "";
    frame->argc = argc;
    if (frame->argc > SHELL_SCRIPT_ARG_MAX - 1)
        frame->argc = SHELL_SCRIPT_ARG_MAX - 1;

    for (i = 0; i < frame->argc; i++)
        frame->argv[i] = argv[i];
    for (; i < SHELL_SCRIPT_ARG_MAX; i++)
        frame->argv[i] = NULL;

    return 0;
}

void shell_pop_script_args(void) {
    if (script_frame_depth > 1)
        script_frame_depth--;
}

static const char* shell_script_arg_value(int index) {
    shell_script_frame_t* frame;

    if (script_frame_depth <= 0)
        return "";

    frame = &script_frames[script_frame_depth - 1];
    if (index == 0)
        return frame->name ? frame->name : "";
    if (index < 0 || index > frame->argc)
        return "";

    return frame->argv[index - 1] ? frame->argv[index - 1] : "";
}

static char** shell_build_envp(void) {
    int i;

    for (i = 0; i < shell_env_count; i++) {
        shell_env_strings[i][0] = '\0';
        strncat(shell_env_strings[i], shell_env[i].name, sizeof(shell_env_strings[i]) - 1);
        strncat(shell_env_strings[i], "=", sizeof(shell_env_strings[i]) - strlen(shell_env_strings[i]) - 1);
        strncat(shell_env_strings[i], shell_env[i].value, sizeof(shell_env_strings[i]) - strlen(shell_env_strings[i]) - 1);
        shell_envp[i] = shell_env_strings[i];
    }
    shell_envp[shell_env_count] = NULL;
    return shell_envp;
}

static void shell_init_env(void) {
    script_frames[0].name = "mash";
    script_frames[0].argc = 0;
    shell_setenv("PATH", "/usr/bin:/bin");
    shell_setenv("HOME", "/home/user");
    shell_setenv("USER", "user");
    shell_setenv("PS1", "mash$> ");
}

static char* trim_spaces(char* s) {
    char* end;

    while (*s == ' ' || *s == '\t')
        s++;

    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }

    return s;
}

static int starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s++ != *prefix++)
            return 0;
    }
    return 1;
}

static int shell_is_valid_name(const char* name) {
    if (!name || !shell_var_start(*name))
        return 0;

    name++;
    while (*name) {
        if (!shell_var_char(*name))
            return 0;
        name++;
    }

    return 1;
}

static int shell_apply_assignment(const char* token) {
    char name[SHELL_ENV_NAME_LEN];
    const char* eq;
    size_t name_len;

    eq = strchr(token, '=');
    if (!eq)
        return -1;

    name_len = (size_t)(eq - token);
    if (name_len == 0 || name_len >= sizeof(name))
        return -1;

    memcpy(name, token, name_len);
    name[name_len] = '\0';

    if (!shell_is_valid_name(name))
        return -1;

    return shell_setenv(name, eq + 1);
}

static void shell_apply_rc_line(char* line) {
    char* name;
    char* value;
    char* eq;

    line = trim_spaces(line);
    if (!*line || *line == '#')
        return;

    if (starts_with(line, "export "))
        line = trim_spaces(line + 7);

    eq = strchr(line, '=');
    if (!eq)
        return;

    *eq = '\0';
    name = trim_spaces(line);
    value = trim_spaces(eq + 1);

    if (*value && (*value == '"' || *value == '\'') && value[strlen(value) - 1] == *value) {
        value[strlen(value) - 1] = '\0';
        value++;
    }

    shell_setenv(name, value);
}

static void shell_load_rc_file(const char* path) {
    char buffer[512];
    int fd;
    int n;
    int start = 0;
    int i;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return;

    n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n <= 0)
        return;

    buffer[n] = '\0';
    for (i = 0; i <= n; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\0') {
            buffer[i] = '\0';
            shell_apply_rc_line(&buffer[start]);
            start = i + 1;
        }
    }
}

static void shell_load_startup_files(void) {
    shell_load_rc_file("/home/user/.nl-mashrc");
}

static int build_exec_path_from_dir(const char* dir, int dir_len,
                                    const char* name, char* out, size_t out_size) {
    size_t pos = 0;

    if (token_has_slash(name)) {
        strncpy(out, name, out_size - 1);
        out[out_size - 1] = '\0';
        return 0;
    }

    if (dir_len <= 0) {
        if (out_size < 3)
            return -1;
        out[pos++] = '.';
    } else {
        if ((size_t)dir_len >= out_size)
            return -1;
        memcpy(out, dir, dir_len);
        pos = dir_len;
    }

    if (pos > 0 && out[pos - 1] != '/') {
        if (pos + 1 >= out_size)
            return -1;
        out[pos++] = '/';
    }

    if (pos + strlen(name) >= out_size)
        return -1;

    strcpy(out + pos, name);
    return 0;
}

static int shell_file_looks_text(const char* path) {
    unsigned char buf[64];
    int fd;
    int n;
    int i;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    n = read(fd, buf, sizeof(buf));
    close(fd);

    if (n < 0)
        return 0;
    if (n == 0)
        return 1;
    if (n >= 4 && buf[0] == 0x7f && buf[1] == 'E' &&
        buf[2] == 'L' && buf[3] == 'F')
        return 0;

    for (i = 0; i < n; i++) {
        if (buf[i] == 0)
            return 0;
    }

    return 1;
}

static void exec_script_or_die_if_text(const char* path, int argc, char* argv[]) {
    if (access(path, 0) == 0 && access(path, X_OK) < 0) {
        printf("mash: permission denied: %s\n", path);
        exit(126);
    }

    if (errno == ENOEXEC || shell_file_looks_text(path)) {
        int status = shell_source_file(path, argc - 1, &argv[1]);

        if (status == SHELL_EXIT)
            status = 0;
        exit(status);
    }
}

static int parse_redirections(int* argc, char* argv[], shell_redirs_t* redirs) {
    int src = 0;
    int dst = 0;

    redirs->input = NULL;
    redirs->output = NULL;
    redirs->error = NULL;
    redirs->output_append = 0;
    redirs->error_append = 0;

    while (src < *argc) {
        int target_fd = -1;
        int op_index = src;
        const char* op = argv[src];

        if ((strcmp(argv[src], "1") == 0 || strcmp(argv[src], "2") == 0) &&
            src + 1 < *argc &&
            (strcmp(argv[src + 1], ">") == 0 || strcmp(argv[src + 1], ">>") == 0)) {
            target_fd = argv[src][0] - '0';
            op_index = src + 1;
            op = argv[op_index];
        } else if ((strcmp(argv[src], "1>") == 0 || strcmp(argv[src], "1>>") == 0 ||
                    strcmp(argv[src], "2>") == 0 || strcmp(argv[src], "2>>") == 0)) {
            target_fd = argv[src][0] - '0';
            op = argv[src] + 1;
        }

        if (strcmp(argv[src], "<") == 0 ||
            strcmp(argv[src], ">") == 0 ||
            strcmp(argv[src], ">>") == 0 ||
            target_fd >= 0) {
            int is_input = strcmp(op, "<") == 0;
            int is_append = strcmp(op, ">>") == 0;
            int target_index = op_index + 1;

            if (target_index >= *argc) {
                printf("mash: missing redirection target after %s\n", argv[op_index]);
                return -1;
            }

            if (is_input) {
                redirs->input = argv[target_index];
            } else if (target_fd == 2) {
                redirs->error = argv[target_index];
                redirs->error_append = is_append;
            } else {
                redirs->output = argv[target_index];
                redirs->output_append = is_append;
            }
            src = target_index + 1;
            continue;
        }

        argv[dst++] = argv[src++];
    }

    argv[dst] = NULL;
    *argc = dst;
    return 0;
}

static int open_redirect_output(const char* path, int append) {
    int fd;

    if (!append) {
        return open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    }

    fd = open(path, O_WRONLY, 0);
    if (fd < 0)
        fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0)
        lseek(fd, 0, SEEK_END);
    return fd;
}

static int apply_redirections(const shell_redirs_t* redirs) {
    int fd;

    if (redirs->input) {
        fd = open(redirs->input, O_RDONLY, 0);
        if (fd < 0) {
            printf("mash: cannot open input %s\n", redirs->input);
            return -1;
        }
        if (dup2(fd, STDIN_FILENO) < 0) {
            close(fd);
            printf("mash: cannot redirect stdin\n");
            return -1;
        }
        close(fd);
    }

    if (redirs->output) {
        fd = open_redirect_output(redirs->output, redirs->output_append);
        if (fd < 0) {
            printf("mash: cannot open output %s\n", redirs->output);
            return -1;
        }
        if (dup2(fd, STDOUT_FILENO) < 0) {
            close(fd);
            printf("mash: cannot redirect stdout\n");
            return -1;
        }
        close(fd);
    }

    if (redirs->error) {
        fd = open_redirect_output(redirs->error, redirs->error_append);
        if (fd < 0) {
            printf("mash: cannot open stderr %s\n", redirs->error);
            return -1;
        }
        if (dup2(fd, STDERR_FILENO) < 0) {
            close(fd);
            printf("mash: cannot redirect stderr\n");
            return -1;
        }
        close(fd);
    }

    return 0;
}

static int argv_has_pipeline(int argc, char* argv[]) {
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "|") == 0)
            return 1;
    }

    return 0;
}

static void exec_external_or_die(int argc, char* argv[]) {
    char* exec_argv[SHELL_MAX_ARGS];
    char** envp = shell_build_envp();
    char cmd[256];
    const char* path;
    const char* entry;
    int i;

    for (i = 1; i < argc && i < SHELL_MAX_ARGS - 1; i++)
        exec_argv[i] = argv[i];
    exec_argv[i] = NULL;

    if (token_has_slash(argv[0])) {
        build_exec_path_from_dir(NULL, 0, argv[0], cmd, sizeof(cmd));
        exec_argv[0] = cmd;
        execve(cmd, exec_argv, envp);
        exec_script_or_die_if_text(cmd, argc, argv);
    } else {
        path = shell_getenv("PATH");
        if (!path || !*path)
            path = "/bin:/usr/bin";

        entry = path;
        while (*entry) {
            const char* next = strchr(entry, ':');
            int len = next ? (int)(next - entry) : (int)strlen(entry);

            if (build_exec_path_from_dir(entry, len, argv[0], cmd, sizeof(cmd)) == 0) {
                exec_argv[0] = cmd;
                execve(cmd, exec_argv, envp);
                exec_script_or_die_if_text(cmd, argc, argv);
            }

            if (!next)
                break;
            entry = next + 1;
        }
    }

    printf("mash: command not found: %s\n", argv[0]);
    exit(127);
}

static int external_command_exists(const char* name) {
    char cmd[256];
    const char* path;
    const char* entry;

    if (token_has_slash(name)) {
        if (build_exec_path_from_dir(NULL, 0, name, cmd, sizeof(cmd)) < 0)
            return 0;
        return access(cmd, 0) == 0;
    }

    path = shell_getenv("PATH");
    if (!path || !*path)
        path = "/bin:/usr/bin";

    entry = path;
    while (*entry) {
        const char* next = strchr(entry, ':');
        int len = next ? (int)(next - entry) : (int)strlen(entry);

        if (build_exec_path_from_dir(entry, len, name, cmd, sizeof(cmd)) == 0 &&
            access(cmd, 0) == 0)
            return 1;

        if (!next)
            break;
        entry = next + 1;
    }

    return 0;
}

static int split_pipeline(int argc, char* argv[], shell_command_t commands[], int* command_count) {
    int start = 0;
    int count = 0;
    int i;

    for (i = 0; i <= argc; i++) {
        if (i == argc || strcmp(argv[i], "|") == 0) {
            int segment_argc = i - start;

            if (segment_argc == 0) {
                printf("mash: empty command in pipeline\n");
                return -1;
            }

            if (count >= SHELL_MAX_PIPELINE) {
                printf("mash: pipeline too long\n");
                return -1;
            }

            argv[i] = NULL;
            commands[count].argc = segment_argc;
            commands[count].argv = &argv[start];

            if (parse_redirections(&commands[count].argc,
                                   commands[count].argv,
                                   &commands[count].redirs) < 0) {
                return -1;
            }

            if (commands[count].argc == 0) {
                printf("mash: empty command in pipeline\n");
                return -1;
            }

            count++;
            start = i + 1;
        }
    }

    for (i = 0; i < count; i++) {
        if (i > 0 && commands[i].redirs.input) {
            printf("mash: input redirection is only supported on the first pipeline command\n");
            return -1;
        }
        if (i < count - 1 && commands[i].redirs.output) {
            printf("mash: output redirection is only supported on the last pipeline command\n");
            return -1;
        }
    }

    *command_count = count;
    return 0;
}

static int validate_pipeline_commands(shell_command_t commands[], int command_count) {
    int i;

    for (i = 0; i < command_count; i++) {
        const char* name = commands[i].argv[0];

        if (strcmp(name, "exit") == 0 || find_command(name))
            continue;

        if (external_command_exists(name))
            continue;

        printf("mash: command not found: %s\n", name);
        return -1;
    }

    return 0;
}

static void close_pipeline_fds(int pipes[][2], int pipe_count) {
    int i;

    for (i = 0; i < pipe_count; i++) {
        if (pipes[i][0] >= 0)
            close(pipes[i][0]);
        if (pipes[i][1] >= 0)
            close(pipes[i][1]);
    }
}

static void remember_stopped_job(int pid, int pgid, const char* command, int status)
{
    jobs_add(pid, pgid, command);
    jobs_note_status(pid, status);
    printf("\n[stopped] pid %d signal=%d  %s\n",
           pid, WSTOPSIG(status), command ? command : "");
}

static int pipeline_pid_index(const int pids[], int count, int pid)
{
    for (int i = 0; i < count; i++) {
        if (pids[i] == pid)
            return i;
    }
    return -1;
}

static int pipeline_has_stopped_member(const int seen[], const int statuses[], int count)
{
    for (int i = 0; i < count; i++) {
        if (seen[i] && WIFSTOPPED(statuses[i]))
            return 1;
    }
    return 0;
}

static int run_pipeline(int argc, char* argv[], int background) {
    shell_command_t commands[SHELL_MAX_PIPELINE];
    int pipes[SHELL_MAX_PIPELINE - 1][2];
    int pids[SHELL_MAX_PIPELINE];
    int wait_statuses[SHELL_MAX_PIPELINE];
    int wait_seen[SHELL_MAX_PIPELINE];
    int command_count = 0;
    int pipe_count;
    int i;
    int status = 0;
    int last_status = 0;
    int launched = 0;
    int pgid = 0;
    int reported = 0;
    char command[JOBS_COMMAND_LEN];

    for (i = 0; i < SHELL_MAX_PIPELINE - 1; i++) {
        pipes[i][0] = -1;
        pipes[i][1] = -1;
    }
    for (i = 0; i < SHELL_MAX_PIPELINE; i++) {
        wait_statuses[i] = 0;
        wait_seen[i] = 0;
    }

    jobs_build_command(argc, argv, command, sizeof(command));

    if (split_pipeline(argc, argv, commands, &command_count) < 0)
        return SHELL_ERROR;

    if (validate_pipeline_commands(commands, command_count) < 0)
        return SHELL_ERROR;

    pipe_count = command_count - 1;
    for (i = 0; i < pipe_count; i++) {
        if (pipe(pipes[i]) < 0) {
            printf("mash: pipe failed\n");
            close_pipeline_fds(pipes, pipe_count);
            return SHELL_ERROR;
        }
    }

    for (i = 0; i < command_count; i++) {
        int pid = fork();

        if (pid < 0) {
            printf("mash: fork failed\n");
            close_pipeline_fds(pipes, pipe_count);
            for (i = 0; i < launched; i++)
                waitpid(pids[i], &status, 0);
            return SHELL_ERROR;
        }

        if (pid == 0) {
            command_entry_t *entry;

            if (i == 0)
                setpgid(0, 0);
            else if (pgid > 0)
                setpgid(0, pgid);

            signal(SIGINT, SIG_DFL);
            signal(SIGTSTP, SIG_DFL);

            if (i > 0 && dup2(pipes[i - 1][0], STDIN_FILENO) < 0) {
                printf("mash: cannot connect pipeline input\n");
                exit(-1);
            }

            if (i < command_count - 1 && dup2(pipes[i][1], STDOUT_FILENO) < 0) {
                printf("mash: cannot connect pipeline output\n");
                exit(-1);
            }

            close_pipeline_fds(pipes, pipe_count);

            if (apply_redirections(&commands[i].redirs) < 0)
                exit(-1);

            if (strcmp(commands[i].argv[0], "exit") == 0)
                exit(0);

            entry = find_command(commands[i].argv[0]);
            if (entry) {
                int result = entry->function(commands[i].argc, commands[i].argv);
                pflush();
                exit(result);
            }

            exec_external_or_die(commands[i].argc, commands[i].argv);
        }

        pids[i] = pid;
        if (i == 0) {
            pgid = pid;
            setpgid(pid, pgid);
        } else {
            setpgid(pid, pgid);
        }
        launched++;
    }

    close_pipeline_fds(pipes, pipe_count);
    if (background) {
        printf("[bg]");
        for (i = 0; i < command_count; i++) {
            jobs_add(pids[i], pgid, command);
            printf(" pid %d", pids[i]);
        }
        printf("\n");
        return SHELL_OK;
    }

    shell_set_foreground_pgid(pgid);
    while (reported < command_count) {
        int waited = waitpid(-pgid, &status, WUNTRACED);
        int idx;

        if (waited <= 0)
            break;

        idx = pipeline_pid_index(pids, command_count, waited);
        if (idx < 0)
            continue;

        wait_statuses[idx] = status;
        if (!wait_seen[idx]) {
            wait_seen[idx] = 1;
            reported++;
        }
        last_status = status;
    }
    shell_restore_foreground();

    if (pipeline_has_stopped_member(wait_seen, wait_statuses, command_count)) {
        for (i = 0; i < command_count; i++)
            jobs_add(pids[i], pgid, command);
        for (i = 0; i < command_count; i++) {
            if (wait_seen[i])
                jobs_note_status(pids[i], wait_statuses[i]);
        }
        printf("\n[stopped] pgid %d  %s\n", pgid, command);
    }

    return last_status;
}

static int run_builtin_with_redirs(command_entry_t* entry, int argc, char* argv[],
                                  const shell_redirs_t* redirs) {
    int saved_stdin = -1;
    int saved_stdout = -1;
    int saved_stderr = -1;
    int result;

    if (redirs->input) {
        saved_stdin = dup(STDIN_FILENO);
        if (saved_stdin < 0)
            return SHELL_ERROR;
    }

    if (redirs->output) {
        saved_stdout = dup(STDOUT_FILENO);
        if (saved_stdout < 0) {
            if (saved_stdin >= 0)
                close(saved_stdin);
            return SHELL_ERROR;
        }
    }

    if (redirs->error) {
        saved_stderr = dup(STDERR_FILENO);
        if (saved_stderr < 0) {
            if (saved_stdin >= 0)
                close(saved_stdin);
            if (saved_stdout >= 0)
                close(saved_stdout);
            return SHELL_ERROR;
        }
    }

    if (apply_redirections(redirs) < 0) {
        if (saved_stdin >= 0) {
            dup2(saved_stdin, STDIN_FILENO);
            close(saved_stdin);
        }
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
        }
        if (saved_stderr >= 0) {
            dup2(saved_stderr, STDERR_FILENO);
            close(saved_stderr);
        }
        return SHELL_ERROR;
    }

    result = entry->function(argc, argv);
    pflush();

    if (saved_stdin >= 0) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }

    return result;
}

void my_handler(int sig) {
    const char msg[] = "Child: received SIGUSR1\n";
    /* write is async-signal-safe */
    write(1, msg, sizeof(msg)-1);
    exit(58);
}

int test_kill(void) {

    pid_t pid;
    int status = 0;

    printf("Testing signal system call from userspace...\n");
    
    pid = fork();
    if (pid == 0) {
        /* child - writer */
        //signal(SIGUSR1, my_handler);
            struct sigaction sa = {0};

    /* Install the handler for SIGUSR1 with SA_SIGINFO */
    sa.sa_handler = my_handler;
    //sigemptyset(&sa.sa_mask);          /* no signal masked during handler execution */
    sa.sa_flags = SA_RESTART; /* SA_RESTART useful to restart certain syscalls */

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        printf("     SIGACTION ERROR ... 0x%08X\n", my_handler);
        exit(EXIT_FAILURE);
    }
        printf("     Child is writing message ... 0x%08X\n", my_handler);

        long i = 0;
        while(1)
        {
            for(int j=0; j<1000000; j++){

            }

            printf("            Child wait loop tour %u\n", i);
            
            i++;
        }

    } else {
        /* Parent - reader */
        printf(" DAD will send a signal to son ...\n");

        for(int i=0; i<100000; i++)
        {
            for(int j=0; j<10000; j++){

            }

            if( (i%10000) == 0)
                printf(" dad loop before kill %d\n", i);

        }

        printf(" DAD sending signal SIGUSR1 ...\n");
        kill(pid, SIGUSR1);
        waitpid(-1, &status, 0);
        printf("Parent waked up waited_pid %d, son status = %d\n", pid, status);

    }
    
    return 0;
}

int test_pipe(void) {
    int pipefd[2];
    pid_t pid;
    char buffer[100];

    printf("Testing pipe system call from userspace...\n");
    
    if (pipe(pipefd) == -1) {
        printf("PIPE error\n");
        return 1;
    }
    
    pid = fork();
    if (pid == 0) {
        /* Child - writer */
        printf("     Child is writing message ...\n", pipefd[1]);

        close(pipefd[0]);  /* Close read end */
        int nb = write(pipefd[1], "Hello from child!", 17);
        printf("     Child wrote %d chars in pipe ...\n", nb);
        close(pipefd[1]);
        printf("     Child returning ok ...\n");
        exit(0);
    } else {
        /* Parent - reader */
        printf(" DAD is reading message in pipe ...\n");

        close(pipefd[1]);  /* Close write end */
        /*for(int i=0; i<1000000; i++){
            for(int j=0; j<1000; j++);
            if( (i%10000) == 0)
                printf(" dad loop before kill %d\n", i);
        }*/
       int status = -1;
        int waited_pid = waitpid(-1, &status, 0);
        ssize_t n = read(pipefd[0], buffer, sizeof(buffer));
        buffer[n] = '\0';
        printf("Parent read %d bytes from %d: %s\n",n, pipefd[0], buffer);
        close(pipefd[0]);


        printf("Parent did wait for child pid %d - status = %d\n",waited_pid, status);

    }
    
    return 0;
}

int test_execve(void) {
    int version = 11 ;
    
    printf("******************************************************\n");
    printf("*************** HELLO FROM USER SPACE ****************\n");
    printf("*************** This process is going to fork() ******\n");
    printf("******************************************************\n");

    int child_pid = fork();
    if (child_pid == 0) {
        printf("                 ************ Child process running!\n");
        printf("                 ************ Will be exiting with value %d!\n", version);

        const char* path = "/bin/hello2";
        char* name = "hello2";

        printf("                 ************ Process PID: %d about to exec\n", getpid());
            
        char* const argv[] = { name, NULL };
        char* const envp[] = { NULL };
            
        int result = execve(path , argv, envp);
            
        // Si on arrive ici, exec a échoué
        printf("                 ************ Child: exec failed with %d\n", result);
        exit(version);
        
    } else {

        int status = 0;
        printf("Cool thing happened in user space\n");
        printf("Speaking from Parent %d\n", getpid());
        printf("Parent created child PID %d\n", child_pid);
        printf("Waiting for my child process\n");
        printf("Taking a while ......\n");
        printf("Will be exiting soon with status code %d ......\n", version+1);

        int waited_pid = waitpid(child_pid, &status, 0);
        printf("Parent waked up waited_pid %d, son status = %d\n", waited_pid, status);

        return(version+1);
    } 
}

// Display the shell banner
void shell_print_banner(void) {
    printf("\n");
    printf("\033[1;36m");
    printf("  __  __    _    ____  _   _\n");
    printf(" |  \\/  |  / \\  / ___|| | | |\n");
    printf(" | |\\/| | / _ \\ \\___ \\| |_| |\n");
    printf(" | |  | |/ ___ \\ ___) |  _  |\n");
    printf(" |_|  |_/_/   \\_\\____/|_| |_|\n");
    printf("\033[0m");
    printf(" arm-os shell on newlib\n");
    printf(" type 'help' for builtins, PATH=/usr/bin:/bin\n");
    printf("\n");
}

// Display the prompt
void shell_print_prompt(void) {
    const char* ps1 = shell_getenv("PS1");

    printf("%s", ps1 ? ps1 : "mash$> ");
    pflush();
}

static int shell_parse_line_into(char* line, char* argv[],
                                 char* tokens, size_t tokens_size) {
    int argc = 0;
    char* readp = line;
    char* writep = tokens;
    char* endp = tokens + tokens_size - 1;
    
    while (*readp && argc < SHELL_MAX_ARGS - 1) {
        while (*readp == ' ' || *readp == '\t') {
            readp++;
        }
        
        if (*readp == '\0') {
            break;
        }

        argv[argc++] = writep;

        if ((*readp == '&' && readp[1] == '&') ||
            (*readp == '|' && readp[1] == '|') ||
            (*readp == '>' && readp[1] == '>')) {
            if (writep + 2 >= endp)
                break;
            *writep++ = *readp++;
            *writep++ = *readp++;
        } else if (token_is_special(*readp)) {
            if (writep + 1 >= endp)
                break;
            *writep++ = *readp++;
        } else {
            char quote = 0;
            char* token_start = writep;

            while (*readp) {
                if (quote) {
                    if (*readp == quote) {
                        quote = 0;
                        readp++;
                        continue;
                    }
                } else {
                    if (*readp == '\'' || *readp == '"') {
                        quote = *readp++;
                        continue;
                    }
                    if (*readp == ' ' || *readp == '\t' || token_is_special(*readp))
                        break;
                }

                if (*readp == '\\' && readp[1]) {
                    readp++;
                }
                if (!quote && writep == token_start && *readp == '~' &&
                    (readp[1] == '\0' || readp[1] == '/' ||
                     readp[1] == ' ' || readp[1] == '\t' ||
                     token_is_special(readp[1]))) {
                    const char* home = shell_getenv("HOME");

                    if (!home || !*home)
                        home = "/";

                    while (*home && writep < endp)
                        *writep++ = *home++;
                    readp++;
                    continue;
                }
                if (*readp == '$' && quote != '\'') {
                    char var_name[SHELL_ENV_NAME_LEN];
                    int var_len = 0;
                    const char* value;
                    char status_buf[16];

                    readp++;
                    if (*readp == '{') {
                        int basename = 0;

                        readp++;
                        while (shell_var_char(*readp) && var_len < SHELL_ENV_NAME_LEN - 1)
                            var_name[var_len++] = *readp++;
                        while (shell_var_char(*readp))
                            readp++;
                        var_name[var_len] = '\0';

                        if (readp[0] == '#' && readp[1] == '#' &&
                            readp[2] == '*' && readp[3] == '/') {
                            basename = 1;
                            readp += 4;
                        }

                        if (*readp == '}') {
                            readp++;
                            value = shell_getenv(var_name);
                            if (!value)
                                value = "";
                            if (basename) {
                                const char* slash = shell_last_char(value, '/');
                                if (slash)
                                    value = slash + 1;
                            }
                            while (*value && writep < endp)
                                *writep++ = *value++;
                            continue;
                        }

                        if (writep >= endp)
                            break;
                        *writep++ = '$';
                        *writep++ = '{';
                        continue;
                    }
                    if (*readp == '?') {
                        snprintf(status_buf, sizeof(status_buf), "%d", shell_status);
                        value = status_buf;
                        readp++;
                        while (*value && writep < endp)
                            *writep++ = *value++;
                        continue;
                    }
                    if (*readp == '#') {
                        shell_script_frame_t* frame = &script_frames[script_frame_depth - 1];

                        snprintf(status_buf, sizeof(status_buf), "%d", frame->argc);
                        value = status_buf;
                        readp++;
                        while (*value && writep < endp)
                            *writep++ = *value++;
                        continue;
                    }
                    if (*readp >= '0' && *readp <= '9') {
                        value = shell_script_arg_value(*readp - '0');
                        readp++;
                        while (*value && writep < endp)
                            *writep++ = *value++;
                        continue;
                    }
                    if (!shell_var_start(*readp)) {
                        if (writep >= endp)
                            break;
                        *writep++ = '$';
                        continue;
                    }

                    while (shell_var_char(*readp) && var_len < SHELL_ENV_NAME_LEN - 1)
                        var_name[var_len++] = *readp++;
                    while (shell_var_char(*readp))
                        readp++;
                    var_name[var_len] = '\0';

                    value = shell_getenv(var_name);
                    if (!value)
                        value = "";

                    while (*value && writep < endp)
                        *writep++ = *value++;
                    continue;
                }
                if (writep >= endp)
                    break;
                *writep++ = *readp++;
            }
        }

        *writep++ = '\0';

        if (*readp == ' ' || *readp == '\t') {
            readp++;
        }
    }
    
    argv[argc] = NULL;
    return argc;
}

// Parse a line into arguments
int shell_parse_line(char* line, char* argv[]) {
    return shell_parse_line_into(line, argv, token_buffer, sizeof(token_buffer));
}

// Execute a command
int shell_execute(int argc, char* argv[]) {
    int background = 0;
    shell_redirs_t redirs;

    if (argc == 0) {
        return SHELL_OK;
    }

    if (strcmp(argv[argc - 1], "&") == 0) {
        background = 1;
        argv[--argc] = NULL;
        if (argc == 0)
            return SHELL_OK;
    }

    if (argv_has_pipeline(argc, argv))
        return run_pipeline(argc, argv, background);

    if (parse_redirections(&argc, argv, &redirs) < 0)
        return SHELL_ERROR;
    if (argc == 0)
        return SHELL_OK;

    if (argc == 1 && shell_apply_assignment(argv[0]) == 0)
        return SHELL_OK;

    // Command exit built-in
    if (strcmp(argv[0], "exit") == 0) {
        if (shell_is_login_shell()) {
            printf("exit: refusing to terminate the login shell; use shutdown instead\n");
            return SHELL_ERROR;
        }
        printf("Au revoir!\n");
        shell_running = 0;
        return SHELL_EXIT;
    }

    command_entry_t *entry = find_command(argv[0]);

    if(entry)
    {
        if (background) {
            printf("mash: background builtins are not supported\n");
            return SHELL_ERROR;
        }
        return run_builtin_with_redirs(entry, argc, argv, &redirs);
    }
    
    int child_pid = fork();
    if (child_pid == 0) {
        setpgid(0, 0);
        signal(SIGINT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        if (apply_redirections(&redirs) < 0)
            exit(-1);

        exec_external_or_die(argc, argv);
        
    } else {

        setpgid(child_pid, child_pid);

        if (background) {
            char command[JOBS_COMMAND_LEN];

            jobs_build_command(argc, argv, command, sizeof(command));
            jobs_add(child_pid, child_pid, command);
            printf("[bg] pid %d\n", child_pid);
            return SHELL_OK;
        }

        int status = 0;
        int stopped_status = 0;
        int was_stopped = 0;
        char command[JOBS_COMMAND_LEN];

        jobs_build_command(argc, argv, command, sizeof(command));
        shell_set_foreground_pgid(child_pid);
        if (waitpid(child_pid, &status, WUNTRACED) == child_pid &&
            WIFSTOPPED(status)) {
            stopped_status = status;
            was_stopped = 1;
        }
        shell_restore_foreground();
        if (was_stopped)
            remember_stopped_job(child_pid, child_pid, command, stopped_status);
        //printf("SHELL waked up waited_pid %d, son status = %d\n", waited_pid, status);

        return(status);
    } 


    // Command unknown
    //printf("Commande inconnue: ");
    //printf(argv[0]);
    //printf("\n");
    return SHELL_ERROR;
}

static int shell_is_sequence_operator(const char* token) {
    return strcmp(token, ";") == 0 ||
           strcmp(token, "&&") == 0 ||
           strcmp(token, "||") == 0;
}

static int shell_should_execute_segment(const char* previous_op, int last_status) {
    if (!previous_op || strcmp(previous_op, ";") == 0)
        return 1;
    if (strcmp(previous_op, "&&") == 0)
        return last_status == 0;
    if (strcmp(previous_op, "||") == 0)
        return last_status != 0;
    return 1;
}

static int shell_execute_argv_line(int argc, char* argv[]);

static int shell_token_is_word(const char* token, const char* word) {
    return token && strcmp(token, word) == 0;
}

static int shell_execute_arg_range(char* argv[], int start, int end) {
    char* local_argv[SHELL_MAX_ARGS];
    int argc = 0;

    while (start < end && shell_is_sequence_operator(argv[start]))
        start++;
    while (end > start && shell_is_sequence_operator(argv[end - 1]))
        end--;

    if (start >= end)
        return SHELL_OK;

    while (start < end && argc < SHELL_MAX_ARGS - 1)
        local_argv[argc++] = argv[start++];
    local_argv[argc] = NULL;

    if (start < end) {
        printf("mash: command too long in if block\n");
        return SHELL_ERROR;
    }

    return shell_execute_argv_line(argc, local_argv);
}

static int shell_find_then(int argc, char* argv[]) {
    int depth = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (shell_token_is_word(argv[i], "if")) {
            depth++;
        } else if (shell_token_is_word(argv[i], "fi")) {
            if (depth > 0)
                depth--;
        } else if (depth == 0 && shell_token_is_word(argv[i], "then")) {
            return i;
        }
    }

    return -1;
}

static int shell_find_else_or_fi(int argc, char* argv[], int start,
                                 int* else_index, int* fi_index) {
    int depth = 0;
    int i;

    *else_index = -1;
    *fi_index = -1;

    for (i = start; i < argc; i++) {
        if (shell_token_is_word(argv[i], "if")) {
            depth++;
        } else if (shell_token_is_word(argv[i], "fi")) {
            if (depth == 0) {
                *fi_index = i;
                return 0;
            }
            depth--;
        } else if (depth == 0 && shell_token_is_word(argv[i], "else")) {
            *else_index = i;
        }
    }

    return -1;
}

static int shell_execute_if(int argc, char* argv[]) {
    int then_index;
    int else_index;
    int fi_index;
    int cond_status;
    int result;

    then_index = shell_find_then(argc, argv);
    if (then_index < 0) {
        printf("mash: if: missing then\n");
        return SHELL_ERROR;
    }

    if (shell_find_else_or_fi(argc, argv, then_index + 1,
                              &else_index, &fi_index) < 0) {
        printf("mash: if: missing fi\n");
        return SHELL_ERROR;
    }

    cond_status = shell_execute_arg_range(argv, 1, then_index);
    if (cond_status == SHELL_EXIT)
        return SHELL_EXIT;

    if (cond_status == 0) {
        result = shell_execute_arg_range(argv, then_index + 1,
                                        else_index >= 0 ? else_index : fi_index);
    } else if (else_index >= 0) {
        result = shell_execute_arg_range(argv, else_index + 1, fi_index);
    } else {
        result = SHELL_OK;
    }

    return result;
}

#define SHELL_FOR_MAX_ITEMS 32
#define SHELL_FOR_ITEM_LEN  160

static int shell_token_has_glob(const char* token) {
    while (token && *token) {
        if (*token == '*')
            return 1;
        token++;
    }
    return 0;
}

static int shell_glob_match(const char* pattern, const char* text) {
    if (!*pattern)
        return !*text;

    if (*pattern == '*') {
        while (pattern[1] == '*')
            pattern++;
        pattern++;
        if (!*pattern)
            return 1;
        while (*text) {
            if (shell_glob_match(pattern, text))
                return 1;
            text++;
        }
        return shell_glob_match(pattern, text);
    }

    if (*text && *pattern == *text)
        return shell_glob_match(pattern + 1, text + 1);

    return 0;
}

static int shell_add_for_item(char items[][SHELL_FOR_ITEM_LEN],
                              int* count, const char* value) {
    if (*count >= SHELL_FOR_MAX_ITEMS)
        return -1;
    strncpy(items[*count], value, SHELL_FOR_ITEM_LEN - 1);
    items[*count][SHELL_FOR_ITEM_LEN - 1] = '\0';
    (*count)++;
    return 0;
}

static const char* shell_last_char(const char* s, char c) {
    const char* last = NULL;

    while (*s) {
        if (*s == c)
            last = s;
        s++;
    }

    return last;
}

static int shell_split_glob_token(const char* token, char* dir,
                                  char* prefix, char* pattern) {
    const char* slash = shell_last_char(token, '/');

    if (!slash) {
        strcpy(dir, ".");
        prefix[0] = '\0';
        strncpy(pattern, token, SHELL_FOR_ITEM_LEN - 1);
        pattern[SHELL_FOR_ITEM_LEN - 1] = '\0';
        return 0;
    }

    if (slash == token) {
        strcpy(dir, "/");
        strcpy(prefix, "/");
    } else {
        int dir_len = slash - token;

        if (dir_len >= SHELL_FOR_ITEM_LEN - 1)
            return -1;
        memcpy(dir, token, dir_len);
        dir[dir_len] = '\0';
        memcpy(prefix, token, dir_len);
        prefix[dir_len] = '/';
        prefix[dir_len + 1] = '\0';
    }

    strncpy(pattern, slash + 1, SHELL_FOR_ITEM_LEN - 1);
    pattern[SHELL_FOR_ITEM_LEN - 1] = '\0';
    return 0;
}

static int shell_expand_glob_for_item(const char* token,
                                      char items[][SHELL_FOR_ITEM_LEN],
                                      int* count) {
    char dir[SHELL_FOR_ITEM_LEN];
    char prefix[SHELL_FOR_ITEM_LEN];
    char pattern[SHELL_FOR_ITEM_LEN];
    char buf[1024];
    int matched = 0;
    int fd;
    int n;

    if (!shell_token_has_glob(token))
        return shell_add_for_item(items, count, token);

    if (shell_split_glob_token(token, dir, prefix, pattern) < 0)
        return shell_add_for_item(items, count, token);

    fd = open(dir, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return shell_add_for_item(items, count, token);

    while ((n = getdents(fd, buf, sizeof(buf))) > 0) {
        int pos = 0;

        while (pos < n) {
            struct linux_dirent* entry = (struct linux_dirent*)(buf + pos);
            char full[SHELL_FOR_ITEM_LEN];

            if (entry->d_reclen == 0)
                break;

            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0 &&
                (pattern[0] == '.' || entry->d_name[0] != '.') &&
                shell_glob_match(pattern, entry->d_name)) {
                snprintf(full, sizeof(full), "%s%s", prefix, entry->d_name);
                if (shell_add_for_item(items, count, full) < 0) {
                    close(fd);
                    return -1;
                }
                matched = 1;
            }

            pos += entry->d_reclen;
        }
    }

    close(fd);

    if (!matched)
        return shell_add_for_item(items, count, token);

    return 0;
}

static int shell_collect_for_items(char* argv[], int start, int end,
                                   char items[][SHELL_FOR_ITEM_LEN],
                                   int* count) {
    int i;

    *count = 0;
    for (i = start; i < end; i++) {
        if (shell_is_sequence_operator(argv[i]))
            continue;
        if (shell_expand_glob_for_item(argv[i], items, count) < 0) {
            printf("mash: for: too many items\n");
            return -1;
        }
    }

    return 0;
}

static int shell_find_for_in_do_done(int argc, char* argv[],
                                     int* in_index, int* do_index,
                                     int* done_index) {
    int depth = 0;
    int i;

    *in_index = -1;
    *do_index = -1;
    *done_index = -1;

    for (i = 2; i < argc; i++) {
        if (shell_token_is_word(argv[i], "for")) {
            depth++;
        } else if (shell_token_is_word(argv[i], "done")) {
            if (depth == 0) {
                *done_index = i;
                return *in_index >= 0 && *do_index >= 0 ? 0 : -1;
            }
            depth--;
        } else if (depth == 0 && shell_token_is_word(argv[i], "in")) {
            if (*in_index < 0)
                *in_index = i;
        } else if (depth == 0 && shell_token_is_word(argv[i], "do")) {
            *do_index = i;
        }
    }

    return -1;
}

static int shell_execute_for(int argc, char* argv[]) {
    char items[SHELL_FOR_MAX_ITEMS][SHELL_FOR_ITEM_LEN];
    int item_count = 0;
    int in_index;
    int do_index;
    int done_index;
    int i;
    int result = SHELL_OK;

    if (argc < 6 || !shell_is_valid_name(argv[1])) {
        printf("mash: for: expected 'for NAME in ...; do ...; done'\n");
        return SHELL_ERROR;
    }

    if (shell_find_for_in_do_done(argc, argv, &in_index,
                                  &do_index, &done_index) < 0) {
        printf("mash: for: missing in/do/done\n");
        return SHELL_ERROR;
    }

    if (shell_collect_for_items(argv, in_index + 1, do_index,
                                items, &item_count) < 0)
        return SHELL_ERROR;

    for (i = 0; i < item_count; i++) {
        if (shell_setenv(argv[1], items[i]) < 0) {
            printf("mash: for: cannot set %s\n", argv[1]);
            return SHELL_ERROR;
        }

        result = shell_execute_arg_range(argv, do_index + 1, done_index);
        if (result == SHELL_EXIT)
            return result;
    }

    return result;
}

static int shell_execute_argv_line(int argc, char* argv[]) {
    int start = 0;
    int last_status = SHELL_OK;
    const char* previous_op = NULL;

    while (start < argc) {
        int end = start;
        const char* next_op = NULL;
        int segment_argc;
        int depth = 0;

        while (end < argc) {
            if (shell_token_is_word(argv[end], "if")) {
                depth++;
            } else if (shell_token_is_word(argv[end], "for")) {
                depth++;
            } else if (shell_token_is_word(argv[end], "fi") && depth > 0) {
                depth--;
                end++;
                if (depth == 0)
                    break;
                continue;
            } else if (shell_token_is_word(argv[end], "done") && depth > 0) {
                depth--;
                end++;
                if (depth == 0)
                    break;
                continue;
            }
            if (depth == 0 && shell_is_sequence_operator(argv[end]))
                break;
            end++;
        }

        if (end < argc)
            next_op = argv[end];

        segment_argc = end - start;
        if (segment_argc == 0) {
            printf("mash: syntax error near '%s'\n", next_op ? next_op : "newline");
            return SHELL_ERROR;
        }

        if (shell_should_execute_segment(previous_op, last_status)) {
            argv[end] = NULL;
            if (shell_token_is_word(argv[start], "if"))
                last_status = shell_execute_if(segment_argc, &argv[start]);
            else if (shell_token_is_word(argv[start], "for"))
                last_status = shell_execute_for(segment_argc, &argv[start]);
            else
                last_status = shell_execute(segment_argc, &argv[start]);
            if (last_status != SHELL_EXIT)
                shell_status = last_status;
            if (last_status == SHELL_EXIT)
                return SHELL_EXIT;
        }

        if (!next_op)
            break;

        previous_op = next_op;
        start = end + 1;

        if (start >= argc) {
            if (strcmp(previous_op, ";") == 0)
                break;
            printf("mash: expected command after '%s'\n", previous_op);
            return SHELL_ERROR;
        }
    }

    return last_status;
}

static int shell_is_word_boundary_char(char c) {
    return !shell_var_char(c);
}

static int shell_word_equals_at(const char* p, const char* word, int word_len) {
    int i;

    for (i = 0; i < word_len; i++) {
        if (p[i] != word[i])
            return 0;
    }

    return 1;
}

static char* shell_find_control_word(char* s, const char* word) {
    int word_len = strlen(word);
    char quote = 0;
    char* p = s;

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

        if ((p == s || shell_is_word_boundary_char(p[-1])) &&
            shell_word_equals_at(p, word, word_len) &&
            shell_is_word_boundary_char(p[word_len])) {
            return p;
        }

        p++;
    }

    return NULL;
}

static char* shell_skip_separators(char* s) {
    while (*s == ' ' || *s == '\t' || *s == ';')
        s++;
    return s;
}

static void shell_trim_trailing_separators(char* s) {
    char* end = s + strlen(s);

    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == ';')) {
        *--end = '\0';
    }
}

static int shell_execute_for_line(char* line) {
    char list_copy[SHELL_BUFFER_SIZE];
    char body_copy[SHELL_BUFFER_SIZE];
    char list_tokens[SHELL_BUFFER_SIZE];
    char* list_argv[SHELL_MAX_ARGS];
    char items[SHELL_FOR_MAX_ITEMS][SHELL_FOR_ITEM_LEN];
    char var_name[SHELL_ENV_NAME_LEN];
    char* p;
    char* in_word;
    char* do_word;
    char* done_word;
    char* list_start;
    char* body_start;
    int var_len = 0;
    int list_argc;
    int item_count = 0;
    int i;
    int result = SHELL_OK;

    p = trim_spaces(line + 3);
    while (shell_var_char(*p) && var_len < SHELL_ENV_NAME_LEN - 1) {
        var_name[var_len++] = *p++;
    }
    var_name[var_len] = '\0';

    if (!shell_is_valid_name(var_name)) {
        printf("mash: for: invalid variable name\n");
        return SHELL_ERROR;
    }

    in_word = shell_find_control_word(p, "in");
    if (!in_word) {
        printf("mash: for: missing in\n");
        return SHELL_ERROR;
    }

    list_start = in_word + 2;
    do_word = shell_find_control_word(list_start, "do");
    if (!do_word) {
        printf("mash: for: missing do\n");
        return SHELL_ERROR;
    }

    body_start = do_word + 2;
    done_word = shell_find_control_word(body_start, "done");
    if (!done_word) {
        printf("mash: for: missing done\n");
        return SHELL_ERROR;
    }

    *do_word = '\0';
    *done_word = '\0';
    list_start = shell_skip_separators(trim_spaces(list_start));
    body_start = shell_skip_separators(trim_spaces(body_start));
    shell_trim_trailing_separators(list_start);
    shell_trim_trailing_separators(body_start);

    strncpy(list_copy, list_start, sizeof(list_copy) - 1);
    list_copy[sizeof(list_copy) - 1] = '\0';

    list_argc = shell_parse_line_into(list_copy, list_argv,
                                      list_tokens, sizeof(list_tokens));
    if (list_argc <= 0)
        return SHELL_OK;

    if (shell_collect_for_items(list_argv, 0, list_argc,
                                items, &item_count) < 0)
        return SHELL_ERROR;

    for (i = 0; i < item_count; i++) {
        if (shell_setenv(var_name, items[i]) < 0) {
            printf("mash: for: cannot set %s\n", var_name);
            return SHELL_ERROR;
        }

        strncpy(body_copy, body_start, sizeof(body_copy) - 1);
        body_copy[sizeof(body_copy) - 1] = '\0';
        result = shell_execute_line(body_copy);
        if (result == SHELL_EXIT)
            return result;
    }

    return result;
}

static void shell_strip_comment(char* line) {
    char quote = 0;
    char* p = line;
    char previous = '\0';

    while (*p) {
        if (quote) {
            if (*p == quote)
                quote = 0;
        } else {
            if (*p == '\'' || *p == '"') {
                quote = *p;
            } else if (*p == '#' &&
                       (p == line || previous == ' ' || previous == '\t')) {
                *p = '\0';
                return;
            }
        }

        previous = *p;
        p++;
    }
}

int shell_execute_line(char* line) {
    char local_tokens[SHELL_BUFFER_SIZE];
    char* local_argv[SHELL_MAX_ARGS];
    char* trimmed;
    int argc;
    int result;

    if (!line)
        return SHELL_OK;

    shell_strip_comment(line);
    trimmed = trim_spaces(line);
    if (!*trimmed)
        return SHELL_OK;

    if (starts_with(trimmed, "for "))
        return shell_execute_for_line(trimmed);

    argc = shell_parse_line_into(trimmed, local_argv,
                                 local_tokens, sizeof(local_tokens));
    if (argc <= 0)
        return SHELL_OK;

    result = shell_execute_argv_line(argc, local_argv);
    if (result != SHELL_EXIT)
        shell_status = result;
    return result;
}


// Shell main loop
void shell_run(void) {
    shell_print_banner();
    shell_running = 1;
    
    while (shell_running) {
        jobs_reap_background();
        shell_print_prompt();
        
        char* line = shell_read_line();
        if (!line || strlen(line) == 0) {
            continue;
        }

        int result = shell_execute_line(line);
        if (result == SHELL_EXIT) {
            break;
        }
    }
    
    printf("Shell closed\n");
}


int main() {
    int version = 11 ;

    shell_init_env();
    shell_load_startup_files();
    shell_line_edit_init();
    setpgid(0, 0);
    shell_pgid = getpgrp();
    jobs_set_shell_pgid(shell_pgid);
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGCHLD, shell_sigchld_handler);
    shell_restore_foreground();
    command_init();
    shell_run();

    exit(version);

}

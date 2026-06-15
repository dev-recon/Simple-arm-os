#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include "../include/mash.h"
#include "../include/jobs.h"

char input_buffer[SHELL_BUFFER_SIZE];
char* argv_buffer[SHELL_MAX_ARGS];
int shell_running = 0;

static char token_buffer[SHELL_BUFFER_SIZE];

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

static void shell_set_foreground_pgid(int pgid) {
    if (pgid >= 0)
        stty(TTY_STTY_SET_FOREGROUND_PGID, pgid);
}

static void shell_restore_foreground(void) {
    shell_set_foreground_pgid(shell_pgid);
}

typedef struct shell_redirs {
    const char* input;
    const char* output;
    int append;
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

static int shell_setenv(const char* name, const char* value) {
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
    shell_setenv("PATH", "/bin:/usr/bin");
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
    shell_load_rc_file("/home/user/.mashrc");
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

static int parse_redirections(int* argc, char* argv[], shell_redirs_t* redirs) {
    int src = 0;
    int dst = 0;

    redirs->input = NULL;
    redirs->output = NULL;
    redirs->append = 0;

    while (src < *argc) {
        if (strcmp(argv[src], "<") == 0 ||
            strcmp(argv[src], ">") == 0 ||
            strcmp(argv[src], ">>") == 0) {
            int is_input = strcmp(argv[src], "<") == 0;
            int is_append = strcmp(argv[src], ">>") == 0;

            if (src + 1 >= *argc) {
                printf("mash: missing redirection target after %s\n", argv[src]);
                return -1;
            }

            if (is_input) {
                redirs->input = argv[src + 1];
            } else {
                redirs->output = argv[src + 1];
                redirs->append = is_append;
            }
            src += 2;
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
        fd = open_redirect_output(redirs->output, redirs->append);
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
            }

            if (!next)
                break;
            entry = next + 1;
        }
    }

    printf("mash: command not found: %s\n", argv[0]);
    exit(127);
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

static void close_pipeline_fds(int pipes[][2], int pipe_count) {
    int i;

    for (i = 0; i < pipe_count; i++) {
        if (pipes[i][0] >= 0)
            close(pipes[i][0]);
        if (pipes[i][1] >= 0)
            close(pipes[i][1]);
    }
}

static int run_pipeline(int argc, char* argv[], int background) {
    shell_command_t commands[SHELL_MAX_PIPELINE];
    int pipes[SHELL_MAX_PIPELINE - 1][2];
    int pids[SHELL_MAX_PIPELINE];
    int command_count = 0;
    int pipe_count;
    int i;
    int status = 0;
    int last_status = 0;
    int launched = 0;
    int pgid = 0;

    for (i = 0; i < SHELL_MAX_PIPELINE - 1; i++) {
        pipes[i][0] = -1;
        pipes[i][1] = -1;
    }

    if (split_pipeline(argc, argv, commands, &command_count) < 0)
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
        char command[JOBS_COMMAND_LEN];

        jobs_build_command(argc, argv, command, sizeof(command));
        printf("[bg]");
        for (i = 0; i < command_count; i++) {
            jobs_add(pids[i], pgid, command);
            printf(" pid %d", pids[i]);
        }
        printf("\n");
        return SHELL_OK;
    }

    shell_set_foreground_pgid(pgid);
    for (i = 0; i < command_count; i++) {
        if (waitpid(pids[i], &status, 0) == pids[i])
            last_status = status;
    }
    shell_restore_foreground();

    return last_status;
}

static int run_builtin_with_redirs(command_entry_t* entry, int argc, char* argv[],
                                  const shell_redirs_t* redirs) {
    int saved_stdin = -1;
    int saved_stdout = -1;
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

    if (apply_redirections(redirs) < 0) {
        if (saved_stdin >= 0) {
            dup2(saved_stdin, STDIN_FILENO);
            close(saved_stdin);
        }
        if (saved_stdout >= 0) {
            dup2(saved_stdout, STDOUT_FILENO);
            close(saved_stdout);
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
    printf("================================\n");
    printf("    ARM32 mash v1.0    \n");
    printf("   (support fork/exec)     \n");
    printf("================================\n");
    printf("Type 'help' to see available commands\n");
    printf("\n");
}

// Display the prompt
void shell_print_prompt(void) {
    const char* ps1 = shell_getenv("PS1");

    printf("%s", ps1 ? ps1 : "mash$> ");
    pflush();
}

// Parse a line into arguments
int shell_parse_line(char* line, char* argv[]) {
    int argc = 0;
    char* readp = line;
    char* writep = token_buffer;
    char* endp = token_buffer + sizeof(token_buffer) - 1;
    
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

                    readp++;
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

    // Command exit built-in
    if (strcmp(argv[0], "exit") == 0) {
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
        shell_set_foreground_pgid(child_pid);
        waitpid(child_pid, &status, 0);
        shell_restore_foreground();
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

static int shell_execute_argv_line(int argc, char* argv[]) {
    int start = 0;
    int last_status = SHELL_OK;
    const char* previous_op = NULL;

    while (start < argc) {
        int end = start;
        const char* next_op = NULL;
        int segment_argc;

        while (end < argc && !shell_is_sequence_operator(argv[end]))
            end++;

        if (end < argc)
            next_op = argv[end];

        segment_argc = end - start;
        if (segment_argc == 0) {
            printf("mash: syntax error near '%s'\n", next_op ? next_op : "newline");
            return SHELL_ERROR;
        }

        if (shell_should_execute_segment(previous_op, last_status)) {
            argv[end] = NULL;
            last_status = shell_execute(segment_argc, &argv[start]);
            if (last_status == SHELL_EXIT)
                return SHELL_EXIT;
        }

        if (!next_op)
            break;

        previous_op = next_op;
        start = end + 1;

        if (start >= argc) {
            printf("mash: expected command after '%s'\n", previous_op);
            return SHELL_ERROR;
        }
    }

    return last_status;
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

        jobs_reap_background();
        
        int argc = shell_parse_line(line, argv_buffer);
        if (argc > 0) {
            int result = shell_execute_argv_line(argc, argv_buffer);
            if (result == SHELL_EXIT) {
                break;
            }
        }
    }
    
    printf("Shell closed\n");
}


int main() {
    int version = 11 ;

    printf("******************************************************\n");

    shell_init_env();
    shell_load_startup_files();
    shell_line_edit_init();
    setpgid(0, 0);
    shell_pgid = getpgrp();
    signal(SIGINT, SIG_IGN);
    shell_restore_foreground();
    command_init();
    shell_run();

    printf("SHELL EXITING **********************************************\n");

    exit(version);

}

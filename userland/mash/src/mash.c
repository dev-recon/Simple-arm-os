#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include "../include/mash.h"

extern command_entry_t* find_command(const char* name);
extern void list_commands(void);
extern int command_init(void);

static char token_buffer[SHELL_BUFFER_SIZE];

static void shell_reap_background(void) {
    int status = 0;
    int pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        printf("[bg] pid %d done status=%d\n", pid, status);
    }
}

typedef struct shell_redirs {
    const char* input;
    const char* output;
    int append;
} shell_redirs_t;

static int token_is_special(char c) {
    return c == '<' || c == '>' || c == '&' || c == '|';
}

static int token_has_slash(const char* s) {
    while (*s) {
        if (*s == '/')
            return 1;
        s++;
    }
    return 0;
}

static void build_exec_path(const char* name, char* out, size_t out_size, int index) {
    const char* dirs[] = { "/bin/", "/usr/bin/" };

    if (token_has_slash(name)) {
        strncpy(out, name, out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }

    out[0] = '\0';
    strncat(out, dirs[index], out_size - 1);
    strncat(out, name, out_size - strlen(out) - 1);
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
        unlink(path);
        return open(path, O_CREAT | O_WRONLY, 0644);
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
    printf("mash$> ");
    pflush();
}


// Read a command line
char* shell_read_line(void) {
    int pos = 0;
    char c;
    
    while (pos < SHELL_BUFFER_SIZE - 1) {
        c = getc_tty();
        if(!c) continue;
        if (c == '\r' || c == '\n') {
            printf("\n");
            break;
        } else if (c == '\b' || c == 0x7F) {  // Backspace
            if (pos > 0) {
                pos--;
                printf("\b \b");
            }
        } else if (c >= ' ' && c <= '~') {  // Printable characters
            input_buffer[pos++] = c;
            putc_tty(c);
        }
        pflush();
    }
    
    input_buffer[pos] = '\0';
    return input_buffer;
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

        if (*readp == '>' && readp[1] == '>') {
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
        //printf("                 ************ Child process running!\n");
        char* exec_argv[SHELL_MAX_ARGS];
        char* const envp[] = { NULL };
        char cmd[256];
        int i;

        if (apply_redirections(&redirs) < 0)
            exit(-1);

        build_exec_path(argv[0], cmd, sizeof(cmd), 0);
        exec_argv[0] = cmd;
        for (i = 1; i < argc && i < SHELL_MAX_ARGS - 1; i++)
            exec_argv[i] = argv[i];
        exec_argv[i] = NULL;

        execve(cmd, exec_argv, envp);

        if (!token_has_slash(argv[0])) {
            build_exec_path(argv[0], cmd, sizeof(cmd), 1);
            exec_argv[0] = cmd;
            execve(cmd, exec_argv, envp);
        }

        // If we arrive here, exec failed
        printf("exec %s failed\n", argv[0]);
        exit(-1);
        
    } else {

        if (background) {
            printf("[bg] pid %d\n", child_pid);
            return SHELL_OK;
        }

        int status = 0;
        waitpid(child_pid, &status, 0);
        //printf("SHELL waked up waited_pid %d, son status = %d\n", waited_pid, status);

        return(status);
    } 


    // Command unknown
    //printf("Commande inconnue: ");
    //printf(argv[0]);
    //printf("\n");
    return SHELL_ERROR;
}


// Shell main loop
void shell_run(void) {
    shell_print_banner();
    shell_running = 1;
    
    while (shell_running) {
        shell_reap_background();
        shell_print_prompt();
        
        char* line = shell_read_line();
        if (!line || strlen(line) == 0) {
            continue;
        }

        shell_reap_background();
        
        int argc = shell_parse_line(line, argv_buffer);
        if (argc > 0) {
            int result = shell_execute(argc, argv_buffer);
            if (result == SHELL_EXIT) {
                break;
            }
        }
    }
    
    printf("Shell closed\n");
}


int main() {
    int version = 11 ;
    char *cmd1[] = { "hello" , NULL} ;
    char *cmd2[] = { "hello2" , NULL} ;
    char *cmd3[] = { "malloc" , NULL} ;

    printf("******************************************************\n");

    command_init();
    shell_run();
    //shell_execute(1, cmd2);

    //shell_execute(1, cmd2);

    //shell_execute(1, cmd3);

    printf("SHELL EXITING **********************************************\n");

    exit(version);

}

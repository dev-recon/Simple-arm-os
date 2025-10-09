#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include "../include/mash.h"

extern command_entry_t* find_command(const char* name);
extern void list_commands(void);
extern int command_init(void);

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
    char* token = line;
    
    while (*token && argc < SHELL_MAX_ARGS - 1) {
        // Ignore spaces
        while (*token == ' ' || *token == '\t') {
            token++;
        }
        
        if (*token == '\0') {
            break;
        }
        
        argv[argc++] = token;

        // Find the end of the token
        while (*token && *token != ' ' && *token != '\t') {
            token++;
        }
        
        if (*token) {
            *token++ = '\0';
        }
    }
    
    argv[argc] = NULL;
    return argc;
}

// Execute a command
int shell_execute(int argc, char* argv[]) {
    if (argc == 0) {
        return SHELL_OK;
    }

    // Command exit built-in
    if (strcmp(argv[0], "exit") == 0) {
        printf("Au revoir!\n");
        shell_running = 0;
        return SHELL_EXIT;
    }

    command_entry_t *entry = find_command(argv[0]);

    if(entry)
    {
        return entry->function(argc,argv);
    }

    char *dir[] = { "/bin/" , "/usr/bin/"} ;
    char cmd[256];

    strcpy(cmd, dir[0]);
    strcat(cmd, argv[0]);
    
    int child_pid = fork();
    if (child_pid == 0) {
        //printf("                 ************ Child process running!\n");
            
        char* const argv[] = { cmd, NULL };
        char* const envp[] = { NULL };
            
        int result = execve(cmd , argv, envp);

        // If we arrive here, exec failed
        printf("exec %s failed with %d\n", cmd, result);
        exit(-1);
        
    } else {

        int status = 0;
        int waited_pid = waitpid(child_pid, &status, 0);
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
        shell_print_prompt();
        
        char* line = shell_read_line();
        if (!line || strlen(line) == 0) {
            continue;
        }
        
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
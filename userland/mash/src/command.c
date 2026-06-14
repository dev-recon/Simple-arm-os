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
static int cmd_echo(int argc, char* argv[]);
static int cmd_touch(int argc, char* argv[]);
static int cmd_rm(int argc, char* argv[]);
static int cmd_write(int argc, char* argv[]);
static int cmd_clear(int argc, char* argv[]);
static int cmd_info(int argc, char* argv[]);
static int cmd_storage(int argc, char* argv[]);
static int cmd_save(int argc, char* argv[]);
static int cmd_load(int argc, char* argv[]);
static int cmd_ps(int argc, char* argv[]);
static int cmd_yield(int argc, char* argv[]);
static int cmd_fork_test(int argc, char* argv[]);
static int cmd_pstree(int argc, char* argv[]);
static int cmd_pwd(int argc, char* argv[]);
static int cmd_ls(int argc, char *argv[]);
static int cmd_cat(int argc, char *argv[]);
static int cmd_cd(int argc, char *argv[]);
static int cmd_sleep(int argc, char *argv[]);
static int cmd_mkdir(int argc, char *argv[]);
static int cmd_rmdir(int argc, char *argv[]);
static int cmd_kill(int argc, char *argv[]);

int register_command(const char* name, const char* desc, command_func_t function);

// Initialize the command system
int command_init(void) {

    // Initialize the command table
    for (int i = 0; i < MAX_COMMANDS; i++) {
        command_table[i].name = NULL;
        command_table[i].function = NULL;
    }
    command_count = 0;
    
    // Register basic commands (except ls and cat which are now executables)
    register_command("help", "Display this help", cmd_help);
    register_command("echo", "Display text", cmd_echo);
    register_command("touch", "Create an empty file", cmd_touch);
    register_command("rm", "Delete a file", cmd_rm);
    register_command("write", "Write to a file", cmd_write);
    register_command("clear", "Clear the screen", cmd_clear);
    register_command("info", "Display system information", cmd_info);
    register_command("storage", "Manage storage", cmd_storage);
    register_command("save", "Save the FS", cmd_save);
    register_command("load", "Load the FS", cmd_load);
    register_command("ps", "List tasks", cmd_ps);
    register_command("yield", "Yield the CPU", cmd_yield);
    register_command("fork", "Test fork()", cmd_fork_test);
    register_command("yield", "Yield the CPU", cmd_yield);
    register_command("pwd", "Display current directory", cmd_pwd);
    register_command("ls", "List files or directories", cmd_ls);
    register_command("cat", "Read the contents of a file", cmd_cat);
    register_command("cd", "Change the current directory", cmd_cd);
    register_command("sleep", "Sleep for a specified time", cmd_sleep);
    register_command("mkdir", "Create a directory", cmd_mkdir);
    register_command("rmdir", "Remove an empty directory", cmd_rmdir);
    register_command("kill", "Send a signal to a process", cmd_kill);

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

static int cmd_sleep(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: sleep <seconds>\n");
        return 1;
    }

    unsigned int seconds = atoi(argv[1]);

    printf("Sleeping for %u seconds...\n", seconds);
    sleep(seconds);
    printf("Awake!\n");
    return 0;
}

static int cmd_mkdir(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: mkdir <directory>\n");
        return 1;
    }
    if (mkdir(argv[1], 0755) != 0) {
        printf("mkdir: %s: failed\n", argv[1]);
        return 1;
    }
    return 0;
}

static int cmd_rmdir(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: rmdir <directory>\n");
        return 1;
    }
    if (rmdir(argv[1]) != 0) {
        printf("rmdir: %s: failed\n", argv[1]);
        return 1;
    }
    return 0;
}

static int parse_signal_arg(const char *arg) {
    if (strcmp(arg, "-9") == 0 || strcmp(arg, "-KILL") == 0 || strcmp(arg, "-SIGKILL") == 0)
        return SIGKILL;
    if (strcmp(arg, "-15") == 0 || strcmp(arg, "-TERM") == 0 || strcmp(arg, "-SIGTERM") == 0)
        return SIGTERM;
    if (strcmp(arg, "-10") == 0 || strcmp(arg, "-USR1") == 0 || strcmp(arg, "-SIGUSR1") == 0)
        return SIGUSR1;
    if (strcmp(arg, "-12") == 0 || strcmp(arg, "-USR2") == 0 || strcmp(arg, "-SIGUSR2") == 0)
        return SIGUSR2;
    return -1;
}

static int cmd_kill(int argc, char *argv[]) {
    int sig = SIGTERM;
    int pid_arg = 1;
    int pid;

    if (argc < 2) {
        printf("Usage: kill [-9|-KILL|-TERM|-USR1|-USR2] <pid>\n");
        return 1;
    }

    if (argv[1][0] == '-') {
        sig = parse_signal_arg(argv[1]);
        if (sig < 0 || argc < 3) {
            printf("kill: invalid signal or missing pid\n");
            return 1;
        }
        pid_arg = 2;
    }

    pid = atoi(argv[pid_arg]);
    if (pid <= 0) {
        printf("kill: invalid pid %s\n", argv[pid_arg]);
        return 1;
    }

    if (kill(pid, sig) < 0) {
        printf("kill: failed pid=%d sig=%d\n", pid, sig);
        return 1;
    }

    return 0;
}

static int cmd_cd(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: cd <directory>\n");
        return 1;
    }

    return chdir(argv[1]);

}

static int cmd_cat(int argc, char* argv[]) {
    char buffer[256];
    int n;

    if (argc < 2) {
        while ((n = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
            if (write(STDOUT_FILENO, buffer, n) != n)
                return 1;
        }
        return n < 0 ? 1 : 0;
    }

    int fd = open(argv[1], O_RDONLY , 0);
    if(fd >= 0) {
        struct stat st;
        fstat(fd, &st);
        int i = 0;
        char *buffer = malloc(st.st_size+1);
        read(fd, buffer, st.st_size);
        while( i < st.st_size)
            putc_tty(buffer[i++]);
        close(fd);
        free(buffer);
    } else {
        printf("Error: %d\n", fd);
        return fd;
    }
    
    return 0;
}

// Simple implementation of 'ls' command using getdents syscall
/* Construit la chaîne de permissions rwxrwxrwx à partir de st_mode. */
static void ls_perm_string(mode_t mode, char *out) {
    out[0] = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : '-';
    out[1] = (mode & 0400) ? 'r' : '-';
    out[2] = (mode & 0200) ? 'w' : '-';
    out[3] = (mode & 0100) ? 'x' : '-';
    out[4] = (mode & 0040) ? 'r' : '-';
    out[5] = (mode & 0020) ? 'w' : '-';
    out[6] = (mode & 0010) ? 'x' : '-';
    out[7] = (mode & 0004) ? 'r' : '-';
    out[8] = (mode & 0002) ? 'w' : '-';
    out[9] = (mode & 0001) ? 'x' : '-';
    out[10] = '\0';
}

/* Convertit un timestamp Unix en "Mmm DD HH:MM" (pas de gmtime dans la libc). */
static void ls_format_time(uint32_t ts, char *out) {
    static const char *mon[12] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

    ts /= 60;
    uint32_t min  = ts % 60; ts /= 60;
    uint32_t hour = ts % 24; ts /= 24;
    uint32_t days = ts;

    uint32_t year = 1970;
    for (;;) {
        int leap = (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
        uint32_t yd = 365u + (uint32_t)leap;
        if (days < yd) break;
        days -= yd;
        year++;
    }
    int leap = (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
    int m = 0;
    for (m = 0; m < 12; m++) {
        int md = mdays[m] + (m == 1 && leap ? 1 : 0);
        if ((int)days < md) break;
        days -= (uint32_t)md;
    }
    sprintf(out, "%s %2u %02u:%02u", mon[m], days + 1, hour, min);
}

static int cmd_ls(int argc, char *argv[]) {
    int long_fmt = 0;
    const char *path = ".";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0)
            long_fmt = 1;
        else if (argv[i][0] != '-')
            path = argv[i];
    }

    char *buf = malloc(BUF_SIZE);
    if (!buf) return 1;

    int fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) { free(buf); return 1; }

    ssize_t n;
    while ((n = getdents(fd, buf, BUF_SIZE)) > 0) {
        char *ptr = buf;
        while (ptr < buf + n) {
            struct {
                uint32_t d_ino;
                uint32_t d_off;
                uint16_t d_reclen;
                uint8_t  d_type;
                char     d_name[];
            } *entry = (void*)ptr;

            if (entry->d_reclen == 0) break;

            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0 &&
                entry->d_ino != 0) {

                if (long_fmt) {
                    /* Chemin complet pour stat */
                    char fullpath[512];
                    int plen = strlen(path);
                    memcpy(fullpath, path, (size_t)plen);
                    if (plen > 0 && fullpath[plen - 1] != '/') fullpath[plen++] = '/';
                    strcpy(fullpath + plen, entry->d_name);

                    struct stat st;
                    if (stat(fullpath, &st) == 0) {
                        char perms[11];
                        char tstr[16];
                        ls_perm_string(st.st_mode, perms);
                        ls_format_time((uint32_t)st.st_mtime, tstr);
                        int nl = S_ISDIR(st.st_mode) ? 2 : 1;
                        if (S_ISDIR(st.st_mode))
                            printf("%s %d root root %8u %s \033[1;34m%s\033[0m\n",
                                   perms, nl, (uint32_t)st.st_size, tstr, entry->d_name);
                        else
                            printf("%s %d root root %8u %s %s\n",
                                   perms, nl, (uint32_t)st.st_size, tstr, entry->d_name);
                    } else {
                        printf("??????????  ? root root        ?            %s\n", entry->d_name);
                    }
                } else {
                    if (entry->d_type == 4)
                        printf("\033[1;34m%s\033[0m\n", entry->d_name);
                    else
                        printf("%s\n", entry->d_name);
                }
            }
            ptr += entry->d_reclen;
        }
    }

    if (n < 0) { close(fd); free(buf); return 1; }
    close(fd);
    free(buf);
    return 0;
}

// === Implementation of commands ===
static int cmd_pwd(int argc, char* argv[]) {
    (void)argc; (void)argv;
    printf("%s\n", getcwd(NULL, 0));
    return 0;
}

static int cmd_help(int argc, char* argv[]) {
    (void)argc; (void)argv;
    list_commands();
    return 0;
}

static int cmd_echo(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        printf(argv[i]);
        if (i < argc - 1) {
            printf(" ");
        }
    }
    printf("\n");
    return 0;
}

static int cmd_touch(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: touch <file>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_CREAT | O_RDWR, 0);
    if(fd) {
        printf("File %s created\n",argv[1]);
        close(fd);
    } else {
        printf("Erreur: %d\n", fd);
        return fd;
    }
    
    return 0;
}

static int cmd_rm(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: rm <file>\n");
        return 1;
    }

    int result = 0;

    int fd = open(argv[1], O_RDONLY,0);
    if (fd >= 0) {
        close(fd);
        printf("File exists, now unlinking...\n");

        /* Remove the file */
        if ((result = unlink(argv[1])) == 0)
            printf("File removed successfully\n");
        
    } else {
        printf("Error: %d\n", result);
    }

    return result;
}

static int cmd_write(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: write <file> <text...>\n");
        return 1;
    }
    
    int fd = open(argv[1], O_APPEND | O_WRONLY , 0);
    if(!fd) {
        printf("File %s does not exist, creating it...\n",argv[1]);
    }

    fd = open(argv[1], O_CREAT | O_WRONLY  , 0);
    if (fd < 0) {
        printf("Error: cannot open %s\n",argv[1]);
        return 1;
    }
    
    // Write all arguments starting from the 2nd
    for (int i = 2; i < argc; i++) {
        write(fd, argv[i], strlen(argv[i]));
        if (i < argc - 1) {
            write(fd, " ", 1);
        }
    }
    write(fd, "\n", 1);
    
    close(fd);
    printf("Text written to %s\n", argv[1]);
    
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

static int cmd_ps(int argc, char *argv[]) {
    (void)argc; (void)argv;

    struct sysinfo_response *info = malloc(sizeof(struct sysinfo_response));
    if (!info) { printf("ps: out of memory\n"); return 1; }

    int n = getsysinfo(info);
    if (n < 0) {
        printf("ps: getsysinfo failed\n");
        free(info);
        return 1;
    }

    /* Ligne mémoire */
    unsigned used_kb = info->mem_total_kb - info->mem_free_kb;
    unsigned pct = info->mem_total_kb ? (used_kb * 100 / info->mem_total_kb) : 0;
    printf("\033[1mMem:\033[0m  %u MB total   %u MB free   \033[%sm%u%%\033[0m used\n\n",
           info->mem_total_kb / 1024, info->mem_free_kb / 1024,
           pct > 80 ? "1;31" : pct > 60 ? "1;33" : "1;32", pct);

    /* Header */
    printf("\033[1m%5s %5s %4s %6s %7s %7s %6s  %-8s  %s\033[0m\n",
           "PID", "PPID", "PRI", "%CPU", "STACK", "HEAP", "CTXSW", "STATE", "NAME");
    printf("----------------------------------------------------------------\n");

    for (int i = 0; i < n; i++) {
        struct proc_info *p = &info->procs[i];

        /* Couleur et libellé d'état */
        const char *color, *sstr;
        switch (p->state) {
            case 'R': color = "\033[1;32m"; sstr = "running"; break;
            case 'Z': color = "\033[1;31m"; sstr = "zombie";  break;
            case 'T': color = "\033[0;31m"; sstr = "term";    break;
            case 'D': color = "\033[1;33m"; sstr = "wait";    break;
            default:  color = "\033[0;37m"; sstr = "sleep";   break;
        }

        /* Couleur %CPU */
        unsigned ci = p->cpu_pct_x10 / 10;
        unsigned cf = p->cpu_pct_x10 % 10;
        const char *cpucolor = ci >= 50 ? "\033[1;31m" :
                               ci >= 20 ? "\033[1;33m" : "\033[0m";

        printf("%5d %5d %4u %s%3u.%u%%\033[0m %5uKB %5uKB %6u  %s%-8s\033[0m  %s\n",
               p->pid, p->ppid, p->priority,
               cpucolor, ci, cf,
               p->stack_kb, p->heap_kb,
               p->switches,
               color, sstr,
               p->name);
    }

    free(info);
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

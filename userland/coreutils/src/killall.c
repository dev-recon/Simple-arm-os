#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "arm_os_abi.h"

static struct sysinfo_response killall_sysinfo;

static int parse_signal(const char *s)
{
    if (!s || s[0] != '-')
        return SIGTERM;
    s++;
    if (strcmp(s, "9") == 0 || strcmp(s, "KILL") == 0 || strcmp(s, "SIGKILL") == 0)
        return SIGKILL;
    if (strcmp(s, "2") == 0 || strcmp(s, "INT") == 0 || strcmp(s, "SIGINT") == 0)
        return SIGINT;
    if (strcmp(s, "15") == 0 || strcmp(s, "TERM") == 0 || strcmp(s, "SIGTERM") == 0)
        return SIGTERM;
    if (strcmp(s, "STOP") == 0 || strcmp(s, "SIGSTOP") == 0)
        return SIGSTOP;
    if (strcmp(s, "CONT") == 0 || strcmp(s, "SIGCONT") == 0)
        return SIGCONT;
    if (strcmp(s, "21") == 0 || strcmp(s, "TTIN") == 0 || strcmp(s, "SIGTTIN") == 0)
        return SIGTTIN;
    if (strcmp(s, "22") == 0 || strcmp(s, "TTOU") == 0 || strcmp(s, "SIGTTOU") == 0)
        return SIGTTOU;
    return -1;
}

int main(int argc, char **argv)
{
    int sig = SIGTERM;
    int first = 1;
    int killed = 0;
    pid_t self = getpid();

    if (argc > 1 && argv[1][0] == '-') {
        sig = parse_signal(argv[1]);
        first = 2;
    }

    if (sig < 0 || first >= argc) {
        printf("usage: killall [-SIGNAL] NAME...\n");
        return 1;
    }

    if (getsysinfo(&killall_sysinfo) < 0) {
        printf("killall: cannot read process table\n");
        return 1;
    }

    for (int name = first; name < argc; name++) {
        int matched = 0;
        for (int i = 0; i < killall_sysinfo.proc_count; i++) {
            struct proc_info *p = &killall_sysinfo.procs[i];
            if (p->pid <= 0 || p->pid == self)
                continue;
            if (strcmp(p->name, argv[name]) != 0)
                continue;
            matched = 1;
            if (kill(p->pid, sig) == 0)
                killed++;
            else
                printf("killall: cannot signal %s pid %d\n", argv[name], p->pid);
        }
        if (!matched)
            printf("killall: no process found matching %s\n", argv[name]);
    }

    return killed > 0 ? 0 : 1;
}

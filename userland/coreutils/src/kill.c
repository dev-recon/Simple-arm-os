#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static int parse_signal(const char *arg)
{
    if (strcmp(arg, "-9")       == 0 || strcmp(arg, "-KILL")    == 0 || strcmp(arg, "-SIGKILL") == 0) return SIGKILL;
    if (strcmp(arg, "-15")      == 0 || strcmp(arg, "-TERM")    == 0 || strcmp(arg, "-SIGTERM") == 0) return SIGTERM;
    if (strcmp(arg, "-10")      == 0 || strcmp(arg, "-USR1")    == 0 || strcmp(arg, "-SIGUSR1") == 0) return SIGUSR1;
    if (strcmp(arg, "-12")      == 0 || strcmp(arg, "-USR2")    == 0 || strcmp(arg, "-SIGUSR2") == 0) return SIGUSR2;
    return -1;
}

static const char *signal_name(int sig)
{
    switch (sig) {
        case SIGKILL: return "SIGKILL";
        case SIGTERM: return "SIGTERM";
        case SIGUSR1: return "SIGUSR1";
        case SIGUSR2: return "SIGUSR2";
        default:      return "signal";
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: kill [-9|-KILL|-TERM|-USR1|-USR2] <pid>...\n");
        return 1;
    }

    int sig = SIGTERM;
    int pid_start = 1;

    if (argv[1][0] == '-') {
        sig = parse_signal(argv[1]);
        if (sig < 0 || argc < 3) {
            printf("kill: invalid signal or missing pid\n");
            return 1;
        }
        pid_start = 2;
    }

    int status = 0;
    for (int i = pid_start; i < argc; i++) {
        int pid = atoi(argv[i]);
        if (pid <= 0) {
            printf("kill: invalid pid '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        if (kill(pid, sig) < 0) {
            printf("kill: failed to signal pid %d\n", pid);
            status = 1;
        } else {
            printf("kill: sent %s to pid %d\n", signal_name(sig), pid);
        }
    }
    return status;
}

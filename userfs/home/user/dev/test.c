#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

static unsigned parse_uint_arg(const char *arg, unsigned fallback)
{
    int value;

    if (!arg)
        return fallback;

    value = atoi(arg);
    if (value <= 0)
        return fallback;

    return (unsigned)value;
}

int main( int argc, char** argv ) {

    int cpt = 50;
    int status = 0;

    if(argc > 1)
        cpt = parse_uint_arg(argv[1], 50);

    while(cpt--) {
        int pid=0;
        pid = fork();
        if( pid == 0 ) {
           sleep(1);
           exit(cpt);
        }
        waitpid(-1, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child %d exited with status: %d\n", cpt, WEXITSTATUS(status));
        } else {
            printf("Child did not exit successfully.\n");
        }
    }

    exit(0);
}


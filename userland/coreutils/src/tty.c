#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char path[128];
    int silent = 0;
    int n;

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "-s") != 0)) {
        printf("usage: tty [-s]\n");
        return 1;
    }

    if (argc == 2)
        silent = 1;

    if (!isatty(STDIN_FILENO)) {
        if (!silent)
            printf("not a tty\n");
        return 1;
    }

    n = readlink("/proc/self/fd/0", path, sizeof(path) - 1);
    if (n < 0) {
        if (!silent)
            printf("/dev/tty\n");
        return 0;
    }

    path[n] = '\0';
    if (!silent)
        printf("%s\n", path);

    return 0;
}

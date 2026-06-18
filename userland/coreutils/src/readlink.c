#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    char buf[512];
    int status = 0;

    if (argc < 2) {
        printf("Usage: readlink FILE...\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        int n = readlink(argv[i], buf, sizeof(buf) - 1);
        if (n < 0) {
            printf("readlink: cannot read '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        buf[n] = '\0';
        printf("%s\n", buf);
    }

    return status;
}

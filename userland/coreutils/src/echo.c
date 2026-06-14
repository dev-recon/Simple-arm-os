#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
    int i = 1;
    int newline = 1;

    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        newline = 0;
        i = 2;
    }

    for (; i < argc; i++) {
        printf("%s", argv[i]);
        if (i < argc - 1)
            printf(" ");
    }

    if (newline)
        printf("\n");

    return 0;
}

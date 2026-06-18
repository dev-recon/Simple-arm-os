#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char *end;
    char *base;

    if (argc < 2) {
        printf("usage: basename PATH [SUFFIX]\n");
        return 1;
    }

    end = argv[1] + strlen(argv[1]);
    while (end > argv[1] + 1 && end[-1] == '/')
        *--end = '\0';

    base = strrchr(argv[1], '/');
    base = base ? base + 1 : argv[1];

    if (argc > 2) {
        size_t blen = strlen(base);
        size_t slen = strlen(argv[2]);
        if (slen < blen && strcmp(base + blen - slen, argv[2]) == 0)
            base[blen - slen] = '\0';
    }

    printf("%s\n", *base ? base : "/");
    return 0;
}

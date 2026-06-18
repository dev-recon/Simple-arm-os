#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int open_arg(const char *path)
{
    if (path[0] == '-' && path[1] == '\0')
        return STDIN_FILENO;
    return open(path, O_RDONLY, 0);
}

int main(int argc, char **argv)
{
    int a, b;
    unsigned long pos = 1;
    unsigned long line = 1;

    if (argc != 3) {
        printf("usage: cmp FILE1 FILE2\n");
        return 1;
    }

    a = open_arg(argv[1]);
    b = open_arg(argv[2]);
    if (a < 0 || b < 0) {
        printf("cmp: cannot open input\n");
        if (a >= 0 && a != STDIN_FILENO) close(a);
        if (b >= 0 && b != STDIN_FILENO) close(b);
        return 2;
    }

    for (;;) {
        unsigned char ca, cb;
        int na = read(a, &ca, 1);
        int nb = read(b, &cb, 1);
        if (na < 0 || nb < 0)
            return 2;
        if (na == 0 && nb == 0)
            break;
        if (na == 0 || nb == 0 || ca != cb) {
            printf("%s %s differ: byte %lu, line %lu\n", argv[1], argv[2], pos, line);
            if (a != STDIN_FILENO) close(a);
            if (b != STDIN_FILENO) close(b);
            return 1;
        }
        if (ca == '\n')
            line++;
        pos++;
    }

    if (a != STDIN_FILENO) close(a);
    if (b != STDIN_FILENO) close(b);
    return 0;
}

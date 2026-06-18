#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

typedef struct counts {
    unsigned long lines;
    unsigned long words;
    unsigned long bytes;
} counts_t;

static int wc_fd(int fd, counts_t *c)
{
    char buf[512];
    int n;
    int in_word = 0;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        c->bytes += (unsigned long)n;
        for (int i = 0; i < n; i++) {
            char ch = buf[i];
            int sep = ch == ' ' || ch == '\t' || ch == '\n' ||
                      ch == '\r' || ch == '\v' || ch == '\f';
            if (ch == '\n')
                c->lines++;
            if (sep) {
                in_word = 0;
            } else if (!in_word) {
                c->words++;
                in_word = 1;
            }
        }
    }

    return n < 0 ? 1 : 0;
}

static void print_counts(const counts_t *c, const char *name)
{
    if (name)
        printf("%7lu %7lu %7lu %s\n", c->lines, c->words, c->bytes, name);
    else
        printf("%7lu %7lu %7lu\n", c->lines, c->words, c->bytes);
}

int main(int argc, char **argv)
{
    counts_t total = {0, 0, 0};
    int status = 0;

    if (argc == 1) {
        counts_t c = {0, 0, 0};
        status = wc_fd(STDIN_FILENO, &c);
        print_counts(&c, NULL);
        return status;
    }

    for (int i = 1; i < argc; i++) {
        counts_t c = {0, 0, 0};
        int fd = open(argv[i], O_RDONLY, 0);
        if (fd < 0) {
            printf("wc: cannot open '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        if (wc_fd(fd, &c) != 0)
            status = 1;
        close(fd);
        print_counts(&c, argv[i]);
        total.lines += c.lines;
        total.words += c.words;
        total.bytes += c.bytes;
    }

    if (argc > 2)
        print_counts(&total, "total");

    return status;
}

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *read_line(int fd)
{
    size_t cap = 128, len = 0;
    char *line = malloc(cap);
    char ch;
    int n;

    if (!line)
        return NULL;
    while ((n = read(fd, &ch, 1)) == 1) {
        if (len + 2 > cap) {
            char *next;
            cap *= 2;
            next = realloc(line, cap);
            if (!next) {
                free(line);
                return NULL;
            }
            line = next;
        }
        line[len++] = ch;
        if (ch == '\n')
            break;
    }
    if (n < 0 || (n == 0 && len == 0)) {
        free(line);
        return NULL;
    }
    line[len] = '\0';
    return line;
}

static int cmp_line(const void *a, const void *b)
{
    const char * const *sa = a;
    const char * const *sb = b;
    return strcmp(*sa, *sb);
}

static int collect_fd(int fd, char ***lines, size_t *count, size_t *cap)
{
    char *line;
    while ((line = read_line(fd)) != NULL) {
        if (*count >= *cap) {
            char **next;
            *cap = *cap ? *cap * 2 : 64;
            next = realloc(*lines, *cap * sizeof(char *));
            if (!next) {
                free(line);
                return 1;
            }
            *lines = next;
        }
        (*lines)[(*count)++] = line;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char **lines = NULL;
    size_t count = 0, cap = 0;
    int status = 0;

    if (argc == 1) {
        status = collect_fd(STDIN_FILENO, &lines, &count, &cap);
    } else {
        for (int i = 1; i < argc; i++) {
            int fd = open(argv[i], O_RDONLY, 0);
            if (fd < 0) {
                printf("sort: cannot open '%s'\n", argv[i]);
                status = 1;
                continue;
            }
            status |= collect_fd(fd, &lines, &count, &cap);
            close(fd);
        }
    }

    qsort(lines, count, sizeof(char *), cmp_line);
    for (size_t i = 0; i < count; i++) {
        fputs(lines[i], stdout);
        free(lines[i]);
    }
    free(lines);
    return status;
}

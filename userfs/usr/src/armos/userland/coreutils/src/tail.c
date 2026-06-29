/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/tail.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *read_line_fd(int fd)
{
    size_t cap = 128;
    size_t len = 0;
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

static int tail_fd(int fd, int limit)
{
    char **ring = calloc((size_t)limit, sizeof(char *));
    int count = 0;
    int pos = 0;
    char *line;

    if (!ring)
        return 1;

    while ((line = read_line_fd(fd)) != NULL) {
        free(ring[pos]);
        ring[pos] = line;
        pos = (pos + 1) % limit;
        if (count < limit)
            count++;
    }

    for (int i = 0; i < count; i++) {
        int idx = (pos - count + i + limit) % limit;
        fputs(ring[idx], stdout);
        free(ring[idx]);
    }

    free(ring);
    return 0;
}

static int parse_count(const char *s)
{
    int n = atoi(s);
    return n < 0 ? -1 : n;
}

int main(int argc, char **argv)
{
    int lines = 10;
    int first = 1;
    int status = 0;

    if (argc > 2 && strcmp(argv[1], "-n") == 0) {
        lines = parse_count(argv[2]);
        first = 3;
    } else if (argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9') {
        lines = parse_count(argv[1] + 1);
        first = 2;
    }

    if (lines < 0) {
        printf("usage: tail [-n lines] [file...]\n");
        return 1;
    }
    if (lines == 0)
        return 0;

    if (first >= argc)
        return tail_fd(STDIN_FILENO, lines);

    for (int i = first; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY, 0);
        if (fd < 0) {
            printf("tail: cannot open '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        if (argc - first > 1)
            printf("%s==> %s <==\n", i == first ? "" : "\n", argv[i]);
        status |= tail_fd(fd, lines);
        close(fd);
    }

    return status;
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/uniq.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

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

static int uniq_fd(int fd)
{
    char *prev = NULL;
    char *line;

    while ((line = read_line(fd)) != NULL) {
        if (!prev || strcmp(prev, line) != 0)
            fputs(line, stdout);
        free(prev);
        prev = line;
    }
    free(prev);
    return 0;
}

int main(int argc, char **argv)
{
    int fd = STDIN_FILENO;
    int ret;

    if (argc > 2) {
        printf("usage: uniq [file]\n");
        return 1;
    }
    if (argc == 2) {
        fd = open(argv[1], O_RDONLY, 0);
        if (fd < 0) {
            printf("uniq: cannot open '%s'\n", argv[1]);
            return 1;
        }
    }
    ret = uniq_fd(fd);
    if (fd != STDIN_FILENO)
        close(fd);
    return ret;
}

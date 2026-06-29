/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/head.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_count(const char* s, int* out)
{
    int value;

    if (!s || !*s)
        return -1;

    value = atoi(s);
    if (value < 0)
        return -1;

    *out = value;
    return 0;
}

static int head_fd(int fd, int line_limit)
{
    char buffer[512];
    int lines = 0;
    int n;

    if (line_limit == 0)
        return 0;

    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        int start = 0;
        int i;

        for (i = 0; i < n; i++) {
            if (buffer[i] == '\n') {
                lines++;
                if (lines >= line_limit) {
                    int len = i + 1 - start;

                    if (len > 0 &&
                        write(STDOUT_FILENO, buffer + start, len) != len)
                        return 1;
                    return 0;
                }
            }
        }

        if (write(STDOUT_FILENO, buffer, n) != n)
            return 1;
    }

    return n < 0 ? 1 : 0;
}

static int head_file(const char* path, int line_limit)
{
    int fd = open(path, O_RDONLY, 0);
    int status;

    if (fd < 0) {
        printf("head: cannot open %s\n", path);
        return 1;
    }

    status = head_fd(fd, line_limit);
    close(fd);
    return status;
}

int main(int argc, char** argv)
{
    int line_limit = 10;
    int first_file = 1;
    int i;
    int status = 0;

    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        if (argc < 3 || parse_count(argv[2], &line_limit) < 0) {
            printf("Usage: head [-n lines] [file...]\n");
            return 1;
        }
        first_file = 3;
    } else if (argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' &&
               argv[1][1] <= '9') {
        if (parse_count(argv[1] + 1, &line_limit) < 0) {
            printf("Usage: head [-n lines] [file...]\n");
            return 1;
        }
        first_file = 2;
    }

    if (first_file >= argc)
        return head_fd(STDIN_FILENO, line_limit);

    for (i = first_file; i < argc; i++) {
        if (argc - first_file > 1) {
            if (i > first_file)
                printf("\n");
            printf("==> %s <==\n", argv[i]);
        }

        if (head_file(argv[i], line_limit) != 0)
            status = 1;
    }

    return status;
}

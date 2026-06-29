/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/du.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUF_SIZE 4096

struct dirent_raw {
    uint32_t d_ino;
    uint32_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

static int summarize;

static int join_path(char *out, size_t size, const char *dir, const char *name)
{
    int n = snprintf(out, size, "%s%s%s", dir,
                     strcmp(dir, "/") == 0 ? "" : "/", name);
    return n > 0 && (size_t)n < size ? 0 : -1;
}

static unsigned long du_path(const char *path)
{
    struct stat st;
    unsigned long total;
    int fd;
    char *buf;

    if (lstat(path, &st) < 0) {
        printf("du: cannot stat '%s'\n", path);
        return 0;
    }

    total = st.st_blocks ? (unsigned long)st.st_blocks / 2 : ((unsigned long)st.st_size + 1023) / 1024;

    if (S_ISDIR(st.st_mode)) {
        fd = open(path, O_RDONLY | O_DIRECTORY, 0);
        if (fd >= 0) {
            buf = malloc(BUF_SIZE);
            if (buf) {
                for (;;) {
                    int n = getdents(fd, buf, BUF_SIZE);
                    char *ptr = buf;
                    if (n <= 0)
                        break;
                    while (ptr < buf + n) {
                        struct dirent_raw *e = (struct dirent_raw *)ptr;
                        char child[512];
                        if (e->d_reclen == 0)
                            break;
                        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
                            join_path(child, sizeof(child), path, e->d_name) == 0)
                            total += du_path(child);
                        ptr += e->d_reclen;
                    }
                }
                free(buf);
            }
            close(fd);
        }
    }

    if (!summarize)
        printf("%lu\t%s\n", total, path);
    return total;
}

int main(int argc, char **argv)
{
    int first = 1;
    int status = 0;

    if (argc > 1 && strcmp(argv[1], "-s") == 0) {
        summarize = 1;
        first = 2;
    }

    if (first >= argc) {
        unsigned long total = du_path(".");
        if (summarize)
            printf("%lu\t.\n", total);
        return 0;
    }

    for (int i = first; i < argc; i++) {
        unsigned long total = du_path(argv[i]);
        if (summarize)
            printf("%lu\t%s\n", total, argv[i]);
    }

    return status;
}

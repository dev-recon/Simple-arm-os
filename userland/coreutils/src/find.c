/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/find.c
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

static const char *want_name;
static int want_type;

static const char *base_name(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int match_path(const char *path, const struct stat *st)
{
    if (want_name && strcmp(base_name(path), want_name) != 0)
        return 0;
    if (want_type == 'f' && !S_ISREG(st->st_mode))
        return 0;
    if (want_type == 'd' && !S_ISDIR(st->st_mode))
        return 0;
    return 1;
}

static int join_path(char *out, size_t size, const char *dir, const char *name)
{
    int n = snprintf(out, size, "%s%s%s", dir,
                     strcmp(dir, "/") == 0 ? "" : "/", name);
    return n > 0 && (size_t)n < size ? 0 : -1;
}

static int walk(const char *path)
{
    struct stat st;
    char *buf;
    int fd;

    if (lstat(path, &st) < 0) {
        printf("find: cannot stat '%s'\n", path);
        return 1;
    }

    if (match_path(path, &st))
        printf("%s\n", path);

    if (!S_ISDIR(st.st_mode))
        return 0;

    fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return 1;

    buf = malloc(BUF_SIZE);
    if (!buf) {
        close(fd);
        return 1;
    }

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
                walk(child);
            ptr += e->d_reclen;
        }
    }

    free(buf);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    const char *start = ".";

    if (argc > 1 && argv[1][0] != '-') {
        start = argv[1];
        argv++;
        argc--;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            want_name = argv[++i];
        } else if (strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            want_type = argv[++i][0];
            if (want_type != 'f' && want_type != 'd') {
                printf("find: supported types are f and d\n");
                return 1;
            }
        } else {
            printf("usage: find [path] [-name NAME] [-type f|d]\n");
            return 1;
        }
    }

    return walk(start);
}

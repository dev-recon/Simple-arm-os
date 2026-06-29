/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/mkdir.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_one(const char* path)
{
    struct stat st;

    if (mkdir(path, 0755) == 0)
        return 0;

    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 0;

    return -1;
}

static int mkdir_parents(const char* path)
{
    char tmp[512];
    size_t len;

    if (!path || !*path)
        return -1;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';

    for (char* p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir_one(tmp) < 0)
            return -1;
        *p = '/';
    }

    return mkdir_one(tmp);
}

int main(int argc, char **argv)
{
    int parents = 0;
    int first = 1;

    if (argc > 1 && strcmp(argv[1], "-p") == 0) {
        parents = 1;
        first = 2;
    }

    if (argc <= first) {
        printf("Usage: mkdir [-p] <dir>...\n");
        return 1;
    }

    int status = 0;
    for (int i = first; i < argc; i++) {
        if ((parents ? mkdir_parents(argv[i]) : mkdir(argv[i], 0755)) < 0) {
            printf("mkdir: cannot create '%s': %s\n", argv[i], strerror(errno));
            status = 1;
        }
    }
    return status;
}

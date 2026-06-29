/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/df.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "arm_os_abi.h"

static int read_file(const char *path, char *buf, int size)
{
    int fd = open(path, O_RDONLY, 0);
    int n;

    if (fd < 0)
        return -1;
    n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return n;
}

static char *next_line(char **cursor)
{
    char *line;
    char *nl;

    if (!cursor || !*cursor || **cursor == '\0')
        return NULL;

    line = *cursor;
    nl = strchr(line, '\n');
    if (nl) {
        *nl = '\0';
        *cursor = nl + 1;
    } else {
        *cursor = line + strlen(line);
    }
    return line;
}

static unsigned blocks_to_kb(unsigned blocks, unsigned block_size)
{
    if (!blocks || !block_size)
        return 0;
    return (unsigned)(((uint64_t)blocks * block_size) / 1024);
}

int main(void)
{
    char mounts[512];
    char *cursor = mounts;
    char *line;

    if (read_file("/proc/mounts", mounts, sizeof(mounts)) < 0) {
        printf("df: cannot read /proc/mounts\n");
        return 1;
    }

    printf("Filesystem     1K-blocks     Used Available Mounted on\n");
    while ((line = next_line(&cursor)) != NULL) {
        char src[64], target[64], type[32];
        struct statfs st;
        unsigned blocks = 0;
        unsigned used = 0;
        unsigned avail = 0;

        if (sscanf(line, "%63s %63s %31s", src, target, type) == 3) {
            if (strcmp(type, "proc") == 0)
                continue;

            if (statfs(target, &st) < 0)
                continue;

            blocks = blocks_to_kb(st.f_blocks, st.f_bsize);
            avail = blocks_to_kb(st.f_bavail, st.f_bsize);
            used = blocks > avail ? blocks - avail : 0;
            printf("%-14s %9u %8u %9u %s\n", src, blocks, used, avail, target);
        }
    }

    return 0;
}

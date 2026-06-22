/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/free.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static unsigned parse_value(const char *buf, const char *key)
{
    const char *p = strstr(buf, key);
    if (!p)
        return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == ':')
        p++;
    return (unsigned)strtoul(p, NULL, 10);
}

int main(void)
{
    char buf[512];
    unsigned total;
    unsigned free_kb;
    unsigned used;

    if (read_file("/proc/meminfo", buf, sizeof(buf)) < 0) {
        printf("free: cannot read /proc/meminfo\n");
        return 1;
    }

    total = parse_value(buf, "MemTotal");
    free_kb = parse_value(buf, "MemFree");
    used = total > free_kb ? total - free_kb : 0;

    printf("              total        used        free\n");
    printf("Mem:     %10u  %10u  %10u kB\n", total, used, free_kb);
    return 0;
}

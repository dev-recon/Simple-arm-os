/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/nice.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define NICE_PATH_MAX 512

extern char **environ;

static void usage(void)
{
    printf("usage: nice [-n increment] [command [arg...]]\n");
}

static int has_slash(const char *s)
{
    return s && strchr(s, '/') != NULL;
}

static int build_path(const char *dir, int dir_len, const char *name,
                      char *out, int out_size)
{
    int name_len = (int)strlen(name);
    int pos = 0;

    if (dir_len <= 0) {
        if (name_len + 2 > out_size)
            return -1;
        out[pos++] = '.';
    } else {
        if (dir_len + 1 >= out_size)
            return -1;
        memcpy(out, dir, (size_t)dir_len);
        pos = dir_len;
    }

    if (pos > 0 && out[pos - 1] != '/') {
        if (pos + 1 >= out_size)
            return -1;
        out[pos++] = '/';
    }

    if (pos + name_len >= out_size)
        return -1;

    memcpy(out + pos, name, (size_t)name_len + 1);
    return 0;
}

static int find_command(const char *name, char *out, int out_size)
{
    const char *path;
    const char *entry;

    if (!name || !*name)
        return -1;

    if (has_slash(name)) {
        if ((int)strlen(name) >= out_size)
            return -1;
        strcpy(out, name);
        return access(out, X_OK) == 0 ? 0 : -1;
    }

    path = getenv("PATH");
    if (!path || !*path)
        path = "/bin:/usr/bin:/opt/kilo/bin";

    entry = path;
    while (1) {
        const char *next = strchr(entry, ':');
        int len = next ? (int)(next - entry) : (int)strlen(entry);

        if (build_path(entry, len, name, out, out_size) == 0 &&
            access(out, X_OK) == 0)
            return 0;

        if (!next)
            break;
        entry = next + 1;
    }

    return -1;
}

int main(int argc, char **argv)
{
    int inc = 10;
    int cmd_index = 1;
    char path[NICE_PATH_MAX];

    if (argc >= 3 && strcmp(argv[1], "-n") == 0) {
        inc = atoi(argv[2]);
        cmd_index = 3;
    } else if (argc >= 2 && argv[1][0] == '-' && argv[1][1] != '\0' &&
               argv[1][1] >= '0' && argv[1][1] <= '9') {
        inc = atoi(argv[1]);
        cmd_index = 2;
    }

    if (cmd_index >= argc) {
        int prio;
        if (argc > 1 && strcmp(argv[1], "-n") == 0) {
            usage();
            return 1;
        }
        errno = 0;
        prio = getpriority(PRIO_PROCESS, 0);
        if (prio == -1 && errno != 0) {
            printf("nice: cannot read priority\n");
            return 1;
        }
        printf("%d\n", prio);
        return 0;
    }

    if (nice(inc) < 0) {
        printf("nice: cannot change priority\n");
        return 1;
    }

    if (find_command(argv[cmd_index], path, sizeof(path)) < 0) {
        printf("nice: command not found: %s\n", argv[cmd_index]);
        return 127;
    }

    execve(path, &argv[cmd_index], environ);
    printf("nice: cannot execute %s\n", argv[cmd_index]);
    return errno == ENOENT ? 127 : 126;
}

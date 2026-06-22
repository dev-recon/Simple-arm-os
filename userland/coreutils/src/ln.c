/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/ln.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define LN_PATH_MAX 512

static void usage(void)
{
    printf("Usage: ln [-s] [-f] [-n] TARGET LINK_NAME\n");
    printf("       ln [-s] [-f] [-n] TARGET... DIRECTORY\n");
}

static const char* basename_of(const char *path)
{
    const char *base = path;

    if (!path) return "";
    for (const char *p = path; *p; p++) {
        if (*p == '/')
            base = p + 1;
    }
    return base;
}

static int join_path(const char *dir, const char *name, char *out, int out_size)
{
    int dir_len;
    int name_len;
    int need_slash;

    if (!dir || !name || !out || out_size <= 0)
        return -1;

    dir_len = strlen(dir);
    name_len = strlen(name);
    need_slash = dir_len > 0 && dir[dir_len - 1] != '/';

    if (dir_len + need_slash + name_len + 1 > out_size)
        return -1;

    strcpy(out, dir);
    if (need_slash)
        strcat(out, "/");
    strcat(out, name);
    return 0;
}

static int make_link(const char *target, const char *link_name, int symbolic, int force)
{
    int ret;

    if (force)
        unlink(link_name);

    ret = symbolic ? symlink(target, link_name) : link(target, link_name);
    if (ret < 0) {
        printf("ln: cannot create %slink '%s'",
               symbolic ? "symbolic " : "", link_name);
        if (errno == EEXIST)
            printf(": file exists");
        printf("\n");
        return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int symbolic = 0;
    int force = 0;
    int first = 1;
    int status = 0;
    struct stat st;
    int dest_is_dir = 0;

    for (; first < argc; first++) {
        if (strcmp(argv[first], "--") == 0) {
            first++;
            break;
        }
        if (argv[first][0] != '-' || argv[first][1] == '\0')
            break;

        for (const char *opt = argv[first] + 1; *opt; opt++) {
            if (*opt == 's') {
                symbolic = 1;
            } else if (*opt == 'f') {
                force = 1;
            } else if (*opt == 'n') {
                /* Accepted for compatibility. We already do not follow link_name. */
            } else {
                printf("ln: unsupported option '-%c'\n", *opt);
                usage();
                return 1;
            }
        }
    }

    if (argc - first < 2) {
        usage();
        return 1;
    }

    const char *dest = argv[argc - 1];
    if (stat(dest, &st) == 0 && S_ISDIR(st.st_mode))
        dest_is_dir = 1;

    if (argc - first > 2 && !dest_is_dir) {
        printf("ln: target '%s' is not a directory\n", dest);
        return 1;
    }

    for (int i = first; i < argc - 1; i++) {
        char link_path[LN_PATH_MAX];
        const char *link_name = dest;

        if (dest_is_dir) {
            if (join_path(dest, basename_of(argv[i]), link_path, sizeof(link_path)) < 0) {
                printf("ln: path too long: '%s/%s'\n", dest, basename_of(argv[i]));
                status = 1;
                continue;
            }
            link_name = link_path;
        }

        if (make_link(argv[i], link_name, symbolic, force) != 0)
            status = 1;
    }

    return status;
}

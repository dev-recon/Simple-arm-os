/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/cp.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#define BUF_SIZE 512
#define PATH_BUF 512

static const char* base_name(const char* path)
{
    const char* base = path;
    for (const char* p = path; *p; p++) {
        if (*p == '/')
            base = p + 1;
    }
    return *base ? base : path;
}

static void join_path(char* out, size_t out_size, const char* dir, const char* name)
{
    size_t len = strlen(dir);
    snprintf(out, out_size, "%s%s%s", dir, (len > 0 && dir[len - 1] == '/') ? "" : "/", name);
}

static int ensure_parent_dirs(const char* path)
{
    char tmp[PATH_BUF];
    size_t len;

    if (!path || !*path)
        return 1;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';

    for (char* p = tmp + 1; *p; p++) {
        struct stat st;

        if (*p != '/')
            continue;

        *p = '\0';
        if (stat(tmp, &st) < 0) {
            if (mkdir(tmp, 0755) < 0) {
                printf("cp: cannot create directory '%s': %s\n", tmp, strerror(errno));
                *p = '/';
                return 1;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            printf("cp: '%s' is not a directory\n", tmp);
            *p = '/';
            return 1;
        }
        *p = '/';
    }

    return 0;
}

static int copy_file(const char* src_path, const char* dst_path)
{
    char buf[BUF_SIZE];
    int src;
    int dst;
    int n;

    src = open(src_path, O_RDONLY, 0);
    if (src < 0) {
        printf("cp: cannot open '%s': %s\n", src_path, strerror(errno));
        return 1;
    }

    if (ensure_parent_dirs(dst_path) != 0) {
        close(src);
        return 1;
    }

    dst = open(dst_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (dst < 0) {
        printf("cp: cannot create '%s': %s\n", dst_path, strerror(errno));
        close(src);
        return 1;
    }

    while ((n = read(src, buf, BUF_SIZE)) > 0) {
        if (write(dst, buf, n) != n) {
            printf("cp: write error on '%s'\n", dst_path);
            close(src);
            close(dst);
            return 1;
        }
    }

    close(src);
    close(dst);
    if (n < 0) {
        printf("cp: read error on '%s': %s\n", src_path, strerror(errno));
        return 1;
    }
    return 0;
}

static int copy_tree(const char* src_path, const char* dst_path)
{
    struct stat st;
    char buf[1024];
    int fd;
    int n;
    int status = 0;

    if (mkdir(dst_path, 0755) < 0) {
        if (stat(dst_path, &st) < 0 || !S_ISDIR(st.st_mode)) {
            printf("cp: cannot create directory '%s'\n", dst_path);
            return 1;
        }
    }

    fd = open(src_path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        printf("cp: cannot read directory '%s'\n", src_path);
        return 1;
    }

    while ((n = getdents(fd, buf, sizeof(buf))) > 0) {
        int pos = 0;
        while (pos < n) {
            struct linux_dirent* entry = (struct linux_dirent*)(buf + pos);
            char child_src[PATH_BUF];
            char child_dst[PATH_BUF];

            if (entry->d_reclen == 0)
                break;
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                join_path(child_src, sizeof(child_src), src_path, entry->d_name);
                join_path(child_dst, sizeof(child_dst), dst_path, entry->d_name);
                if (lstat(child_src, &st) < 0) {
                    printf("cp: cannot stat '%s'\n", child_src);
                    status = 1;
                } else if (S_ISDIR(st.st_mode)) {
                    if (copy_tree(child_src, child_dst) != 0)
                        status = 1;
                } else if (copy_file(child_src, child_dst) != 0) {
                    status = 1;
                }
            }
            pos += entry->d_reclen;
        }
    }

    if (n < 0)
        status = 1;
    close(fd);
    return status;
}

static int copy_path(const char* src_arg, const char* dst_arg, int recursive)
{
    struct stat st;
    struct stat dst_st;
    char dst_path[PATH_BUF];

    if (lstat(src_arg, &st) < 0) {
        printf("cp: cannot stat '%s'\n", src_arg);
        return 1;
    }

    if (stat(dst_arg, &dst_st) == 0 && S_ISDIR(dst_st.st_mode)) {
        join_path(dst_path, sizeof(dst_path), dst_arg, base_name(src_arg));
    } else {
        snprintf(dst_path, sizeof(dst_path), "%s", dst_arg);
    }

    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            printf("cp: omitting directory '%s'\n", src_arg);
            return 1;
        }
        return copy_tree(src_arg, dst_path);
    }

    return copy_file(src_arg, dst_path);
}

int main(int argc, char **argv)
{
    int recursive = 0;
    int first = 1;
    int status = 0;

    if (argc > 1 && (strcmp(argv[1], "-r") == 0 || strcmp(argv[1], "-R") == 0)) {
        recursive = 1;
        first = 2;
    }

    if (argc - first < 2) {
        printf("Usage: cp [-r] <src>... <dst>\n");
        return 1;
    }

    if (argc - first > 2) {
        struct stat dst_st;
        if (stat(argv[argc - 1], &dst_st) < 0 || !S_ISDIR(dst_st.st_mode)) {
            printf("cp: target '%s' is not a directory\n", argv[argc - 1]);
            return 1;
        }
    }

    for (int i = first; i < argc - 1; i++) {
        if (copy_path(argv[i], argv[argc - 1], recursive) != 0)
            status = 1;
    }

    return status;
}

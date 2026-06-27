/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/vfstest/vfstest.c
 * Layer: Userland / VFS test program
 *
 * Responsibilities:
 * - Exercise VFS edge cases that are too specific for the global syscall smoke
 *   test.
 * - Stress directory mutations with concurrent user processes.
 *
 * Notes:
 * - ArmOS currently rejects unlink/rename/rmdir on open inodes. Linux defers
 *   deletion until the last close; ArmOS keeps the conservative policy until
 *   ext2/FAT32 can safely defer backend block freeing.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arm_os_abi.h>
#include <dirent.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_RESET "\033[0m"

static int failures = 0;
static int verbose = 1;
static int run_parallel_stress = 0;
static char root[64];

static const char *tpath(const char *name)
{
    static char paths[32][160];
    static int slot = 0;
    char *out = paths[slot++ & 31];

    snprintf(out, 160, "%s/%s", root, name);
    return out;
}

static void ok(const char *name)
{
    if (verbose)
        printf(COLOR_GREEN "[OK]" COLOR_RESET " %s\n", name);
}

static void ko(const char *name, int value)
{
    printf(COLOR_RED "[KO]" COLOR_RESET " %s (%d, errno=%d)\n",
           name, value, errno);
    failures++;
}

static int expect(int cond, const char *name, int value)
{
    if (cond) {
        ok(name);
        return 0;
    }
    ko(name, value);
    return -1;
}

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    int ret;

    if (fd < 0)
        return -1;

    ret = write(fd, text, strlen(text));
    close(fd);
    return ret == (int)strlen(text) ? 0 : -1;
}

static void remove_tree(const char *path)
{
    struct stat st;

    if (lstat(path, &st) < 0)
        return;

    if (S_ISDIR(st.st_mode)) {
        char dents[512];
        int fd;
        int n;

        fd = open(path, O_RDONLY | O_DIRECTORY, 0);
        if (fd < 0)
            return;

        while ((n = getdents(fd, dents, sizeof(dents))) > 0) {
            int pos = 0;

            while (pos < n) {
                struct linux_dirent *de = (struct linux_dirent *)(dents + pos);
                char child[192];

                if (de->d_reclen == 0)
                    break;

                if (strcmp(de->d_name, ".") != 0 &&
                    strcmp(de->d_name, "..") != 0) {
                    snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
                    remove_tree(child);
                }

                pos += de->d_reclen;
            }
        }

        close(fd);
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void test_mutation_guards(void)
{
    int fd;
    const char *file = tpath("file.txt");
    const char *renamed = tpath("renamed.txt");
    const char *dir = tpath("dir");
    const char *child = tpath("dir/child");
    const char *noexec_dir = tpath("noexec");
    const char *noexec_file = tpath("noexec/file.txt");

    expect(write_text(file, "vfs") == 0, "create regular file", 0);

    fd = open(file, O_RDONLY | O_DIRECTORY, 0);
    expect(fd < 0, "O_DIRECTORY rejects regular files", fd);
    if (fd >= 0)
        close(fd);

    expect(mkdir(dir, 0755) == 0, "mkdir parent dir", 0);
    expect(mkdir(child, 0755) == 0, "mkdir child dir", 0);
    expect(rename(dir, tpath("dir/child/moved")) < 0,
           "rename refuses directory into descendant", 0);
    expect(rmdir(child) == 0, "cleanup child dir", 0);
    expect(rmdir(dir) == 0, "cleanup parent dir", 0);

    expect(rmdir("/proc") < 0, "rmdir refuses mountpoint", 0);
    expect(rename("/proc", tpath("proc-moved")) < 0,
           "rename refuses mountpoint", 0);

    fd = open(file, O_RDONLY, 0);
    if (expect(fd >= 0, "open lifetime guard setup", fd) == 0) {
        expect(unlink(file) < 0, "unlink refuses open file", 0);
        expect(rename(file, renamed) < 0, "rename refuses open file", 0);
        close(fd);
    }
    expect(unlink(file) == 0, "unlink after close succeeds", 0);

    expect(mkdir(noexec_dir, 0666) == 0, "mkdir no-exec parent", 0);
    fd = open(noexec_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (getuid() == 0) {
        if (fd >= 0)
            close(fd);
        unlink(noexec_file);
        ok("non-root search permission check skipped as root");
    } else {
        expect(fd < 0, "create requires search permission on parent", fd);
        if (fd >= 0) {
            close(fd);
            unlink(noexec_file);
        }
    }
    chmod(noexec_dir, 0755);
    expect(rmdir(noexec_dir) == 0, "cleanup no-exec parent", 0);
}

static int child_stress(int worker)
{
    char dir[160];
    char file[160];
    char renamed[160];

    for (int i = 0; i < 32; i++) {
        snprintf(dir, sizeof(dir), "%s/w%d-%d", root, worker, i);
        snprintf(file, sizeof(file), "%s/file.txt", dir);
        snprintf(renamed, sizeof(renamed), "%s/renamed.txt", dir);

        if (mkdir(dir, 0755) < 0)
            return 10;
        if (write_text(file, "stress") < 0)
            return 11;
        if (rename(file, renamed) < 0)
            return 12;
        if (unlink(renamed) < 0)
            return 13;
        if (rmdir(dir) < 0)
            return 14;
    }

    return 0;
}

static void test_parallel_mutations(void)
{
    enum { WORKERS = 4 };
    int pids[WORKERS];

    for (int i = 0; i < WORKERS; i++) {
        int pid = fork();

        if (pid == 0)
            exit(child_stress(i));
        if (pid < 0) {
            ko("fork VFS stress worker", pid);
            pids[i] = -1;
        } else {
            pids[i] = pid;
        }
    }

    for (int i = 0; i < WORKERS; i++) {
        int status;

        if (pids[i] < 0)
            continue;

        if (waitpid(pids[i], &status, 0) != pids[i]) {
            ko("wait VFS stress worker", pids[i]);
            continue;
        }

        expect(WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "parallel VFS mutation worker exits cleanly", status);
    }
}

static void usage(void)
{
    printf("usage: vfstest [-q|-v] [--stress]\n");
    printf("  --stress   also run concurrent ext2 mutation workers\n");
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            verbose = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--stress") == 0) {
            run_parallel_stress = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            exit(0);
        } else {
            usage();
            exit(1);
        }
    }

    snprintf(root, sizeof(root), "/tmp/vfstest-%d", getpid());
    remove_tree(root);
    if (mkdir(root, 0755) < 0) {
        perror("vfstest: mkdir");
        exit(1);
    }

    if (verbose)
        printf("=== VFS hardening tests ===\n");

    test_mutation_guards();
    expect(child_stress(0) == 0, "serial VFS mutation stress", 0);
    if (run_parallel_stress)
        test_parallel_mutations();

    remove_tree(root);

    if (failures == 0) {
        printf("vfstest: all tests passed\n");
        exit(0);
    }

    printf("vfstest: %d failure(s)\n", failures);
    exit(1);
}

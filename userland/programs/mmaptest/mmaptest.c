/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/mmaptest/mmaptest.c
 * Layer: Userland / diagnostics
 * Description: Smoke test for anonymous private mmap/munmap.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_RESET "\033[0m"

static int fail(const char *msg)
{
    printf(COLOR_RED "[KO]" COLOR_RESET " %s errno=%d\n", msg, errno);
    return 1;
}

static void ok(const char *msg)
{
    printf(COLOR_GREEN "[OK]" COLOR_RESET " %s\n", msg);
}

int main(void)
{
    char *p;
    char *q;
    int status = 0;
    pid_t pid;

    printf("mmaptest: anonymous private mapping smoke test\n");

    p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return fail("mmap 8KB");
    ok("mmap 8KB");

    p[0] = 'A';
    p[4095] = 'B';
    p[4096] = 'C';
    p[8191] = 'D';
    if (p[0] != 'A' || p[4095] != 'B' || p[4096] != 'C' || p[8191] != 'D')
        return fail("read/write across pages");
    ok("read/write across pages");

    pid = fork();
    if (pid < 0)
        return fail("fork after mmap");
    if (pid == 0) {
        p[0] = 'Z';
        return (p[0] == 'Z' && p[4096] == 'C') ? 23 : 24;
    }

    if (waitpid(pid, &status, 0) != pid)
        return fail("wait child");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 23)
        return fail("child sees private mmap");
    if (p[0] != 'A')
        return fail("parent COW preserved");
    ok("fork/COW preserves parent page");

    if (munmap(p + 4096, 4096) < 0)
        return fail("partial munmap second page");
    if (p[0] != 'A' || p[4095] != 'B')
        return fail("first page remains mapped after partial munmap");
    ok("partial munmap keeps first page");

    q = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED)
        return fail("second mmap 4KB");
    strcpy(q, "hello from mmap");
    if (strcmp(q, "hello from mmap") != 0)
        return fail("second mmap read/write");
    ok("second mmap read/write");

    if (munmap(p, 4096) < 0)
        return fail("munmap first mapping");
    if (munmap(q, 4096) < 0)
        return fail("munmap second mapping");
    ok("munmap cleanup");

    printf("mmaptest: all tests passed\n");
    return 0;
}

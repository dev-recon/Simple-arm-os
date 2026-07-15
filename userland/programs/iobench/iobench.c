/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/iobench/iobench.c
 * Layer: Userland / storage diagnostics
 *
 * Responsibilities:
 * - Measure sequential filesystem write, sync and read throughput.
 * - Exercise storage through the normal VFS and POSIX syscall path.
 * - Keep a reusable file for cold-read measurements after reboot when asked.
 *
 * Notes:
 * - The second read is intentionally reported as a warm-cache measurement.
 * - Use -r after a reboot to measure an existing file without rewriting it.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define DEFAULT_PATH       "/tmp/iobench.dat"
#define DEFAULT_MIB        8U
#define DEFAULT_BLOCK_KIB  64U
#define MAX_MIB            256U
#define MAX_BLOCK_KIB      1024U

static unsigned long long now_us(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return 0;
    return (unsigned long long)tv.tv_sec * 1000000ULL +
           (unsigned long long)tv.tv_usec;
}

static unsigned parse_unsigned(const char *text, unsigned fallback)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return fallback;
    value = strtoul(text, &end, 10);
    if (!end || *end != '\0' || value == 0 || value > 0xffffffffUL)
        return fallback;
    return (unsigned)value;
}

static void usage(const char *prog)
{
    printf("usage: %s [-f path] [-m MiB] [-b KiB] [-r] [-k]\n", prog);
    printf("  -r  read an existing file only (useful after reboot)\n");
    printf("  -k  keep the generated benchmark file\n");
}

static int write_full(int fd, const unsigned char *buf, size_t bytes)
{
    size_t done = 0;

    while (done < bytes) {
        ssize_t n = write(fd, buf + done, bytes - done);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static ssize_t read_full(int fd, unsigned char *buf, size_t bytes)
{
    size_t done = 0;

    while (done < bytes) {
        ssize_t n = read(fd, buf + done, bytes - done);
        if (n < 0)
            return -1;
        if (n == 0)
            break;
        done += (size_t)n;
    }
    return (ssize_t)done;
}

static void fill_pattern(unsigned char *buf, size_t bytes, unsigned block)
{
    for (size_t i = 0; i < bytes; i++)
        buf[i] = (unsigned char)((i * 17U + block * 31U) & 0xffU);
}

static void print_rate(const char *label, unsigned long long bytes,
                       unsigned long long elapsed_us)
{
    unsigned long long hundredths;

    if (elapsed_us == 0)
        elapsed_us = 1;
    hundredths = (bytes * 100ULL * 1000000ULL) /
                 (elapsed_us * 1024ULL * 1024ULL);
    printf("%-12s %llu bytes in %llu.%03llu s: %llu.%02llu MiB/s\n",
           label, bytes, elapsed_us / 1000000ULL,
           (elapsed_us / 1000ULL) % 1000ULL,
           hundredths / 100ULL, hundredths % 100ULL);
}

static int run_read_pass(int fd, unsigned char *buf, size_t block_size,
                         unsigned long long total, const char *label)
{
    unsigned long long start;
    unsigned long long elapsed;
    unsigned long long done = 0;
    unsigned checksum = 0;

    if (lseek(fd, 0, SEEK_SET) < 0)
        return -1;
    start = now_us();
    while (done < total) {
        size_t wanted = block_size;
        ssize_t n;

        if ((unsigned long long)wanted > total - done)
            wanted = (size_t)(total - done);
        n = read_full(fd, buf, wanted);
        if (n <= 0)
            return -1;
        for (ssize_t i = 0; i < n; i += 4096)
            checksum = (checksum << 5) ^ (checksum >> 2) ^ buf[i];
        done += (unsigned long long)n;
    }
    elapsed = now_us() - start;
    print_rate(label, done, elapsed);
    printf("  checksum    0x%08x\n", checksum);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = DEFAULT_PATH;
    unsigned mib = DEFAULT_MIB;
    unsigned block_kib = DEFAULT_BLOCK_KIB;
    unsigned long long total;
    size_t block_size;
    unsigned char *buffer;
    int read_only = 0;
    int keep = 0;
    int fd;
    int opt;

    while ((opt = getopt(argc, argv, "f:m:b:rkh")) != -1) {
        switch (opt) {
            case 'f': path = optarg; break;
            case 'm': mib = parse_unsigned(optarg, 0); break;
            case 'b': block_kib = parse_unsigned(optarg, 0); break;
            case 'r': read_only = 1; break;
            case 'k': keep = 1; break;
            default: usage(argv[0]); return opt == 'h' ? 0 : 1;
        }
    }

    if (!mib || mib > MAX_MIB || !block_kib || block_kib > MAX_BLOCK_KIB) {
        usage(argv[0]);
        return 1;
    }

    block_size = (size_t)block_kib * 1024U;
    total = (unsigned long long)mib * 1024ULL * 1024ULL;
    buffer = malloc(block_size);
    if (!buffer) {
        printf("iobench: cannot allocate %u KiB (errno=%d)\n", block_kib, errno);
        return 1;
    }

    if (read_only) {
        struct stat st;

        fd = open(path, O_RDONLY, 0);
        if (fd < 0 || fstat(fd, &st) < 0) {
            perror("iobench: open existing file");
            free(buffer);
            return 1;
        }
        total = (unsigned long long)st.st_size;
    } else {
        unsigned long long start;
        unsigned long long elapsed;
        unsigned long long done = 0;
        unsigned block = 0;

        fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (fd < 0) {
            perror("iobench: create");
            free(buffer);
            return 1;
        }

        start = now_us();
        while (done < total) {
            size_t bytes = block_size;

            if ((unsigned long long)bytes > total - done)
                bytes = (size_t)(total - done);
            fill_pattern(buffer, bytes, block++);
            if (write_full(fd, buffer, bytes) < 0) {
                perror("iobench: write");
                close(fd);
                free(buffer);
                return 1;
            }
            done += bytes;
        }
        elapsed = now_us() - start;
        print_rate("write", done, elapsed);

        start = now_us();
        if (fsync(fd) < 0) {
            perror("iobench: fsync");
            close(fd);
            free(buffer);
            return 1;
        }
        elapsed = now_us() - start;
        printf("%-12s %llu.%03llu s\n", "fsync",
               elapsed / 1000000ULL, (elapsed / 1000ULL) % 1000ULL);
    }

    if (run_read_pass(fd, buffer, block_size, total,
                      read_only ? "read" : "read-1") < 0 ||
        (!read_only && run_read_pass(fd, buffer, block_size, total,
                                     "read-2") < 0)) {
        perror("iobench: read");
        close(fd);
        free(buffer);
        return 1;
    }

    close(fd);
    free(buffer);
    if (!read_only && !keep)
        unlink(path);
    printf("block stats: cat /proc/diskstats\n");
    return 0;
}

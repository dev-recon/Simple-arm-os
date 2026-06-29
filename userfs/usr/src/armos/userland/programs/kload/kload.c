/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/kload/kload.c
 * Layer: Userland / test or sample program
 * Description: Userland test, diagnostic, or sample application.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE          4096U
#define DEFAULT_SECONDS    60U
#define DEFAULT_MEMORY_KB  1024U
#define MAX_MEMORY_KB      8192U
#define MAX_WORKERS        64U
#define MAX_CPU_LOAD       64U
#define MAX_CPU_PERCENT    100U
#define CPU_BATCHES        256U
#define CPU_INNER          1024U

static volatile sig_atomic_t running = 1;

static void on_signal(int sig)
{
    (void)sig;
    running = 0;
}

static unsigned parse_uint_arg(const char *arg, unsigned fallback)
{
    int value;

    if (!arg)
        return fallback;

    value = atoi(arg);
    if (value <= 0)
        return fallback;

    return (unsigned)value;
}

static void usage(const char *prog)
{
    printf("usage: %s [-s seconds] [-m memory_kb] [-c cpu_load] [-u cpu_percent] [-f forks_per_sec] [-p workers]\n", prog);
    printf("example: %s -s 120 -m 2048 -c 4 -u 25 -p 8 -f 1 &\n", prog);
    printf("  -c load    repeats CPU work per loop (default 1, max %u)\n", MAX_CPU_LOAD);
    printf("  -u percent cooperative CPU ceiling per worker (default 100)\n");
    printf("  -p workers creates persistent worker processes (max %u)\n", MAX_WORKERS);
    printf("  -f rate creates short-lived fork/wait churn inside each worker\n");
}

static unsigned long long now_us(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return 0;

    return ((unsigned long long)tv.tv_sec * 1000000ULL) +
           (unsigned long long)tv.tv_usec;
}

static int is_background_job(void)
{
    pid_t fg_pgid = tcgetpgrp(STDIN_FILENO);

    if (fg_pgid < 0)
        return 0;

    return fg_pgid != getpgrp();
}

static void touch_memory(unsigned char *buf, unsigned bytes, unsigned seed)
{
    for (unsigned off = 0; off < bytes; off += PAGE_SIZE)
        buf[off] = (unsigned char)(seed + (off >> 12));
    if (bytes)
        buf[bytes - 1] = (unsigned char)(seed ^ 0xa5U);
}

static void cpu_burst(volatile unsigned *acc)
{
    for (unsigned batch = 0; batch < CPU_BATCHES; batch++) {
        for (unsigned i = 0; i < CPU_INNER; i++) {
            *acc ^= (*acc << 5) + (*acc >> 3) + i + batch;
            *acc = (*acc << 7) | (*acc >> 25);
        }
    }
}

static void poke_procfs(void)
{
    char buf[64];
    int fd = open("/proc/uptime", O_RDONLY, 0);

    if (fd < 0)
        return;

    (void)read(fd, buf, sizeof(buf));
    close(fd);
}

static void fork_once(unsigned char *buf, unsigned bytes, unsigned seed)
{
    int status;
    int pid = fork();

    if (pid == 0) {
        if (buf && bytes)
            touch_memory(buf, bytes > PAGE_SIZE ? PAGE_SIZE : bytes, seed);
        _exit(0);
    }

    if (pid > 0)
        (void)waitpid(pid, &status, 0);
}

static void throttle_cpu(unsigned cpu_percent, unsigned long long active_us)
{
    unsigned long long sleep_us;

    if (cpu_percent >= MAX_CPU_PERCENT || active_us == 0)
        return;

    sleep_us = (active_us * (MAX_CPU_PERCENT - cpu_percent)) / cpu_percent;
    if (sleep_us > 250000ULL)
        sleep_us = 250000ULL;
    if (sleep_us > 0)
        usleep((useconds_t)sleep_us);
}

static int run_worker(unsigned seconds, unsigned memory_kb, unsigned forks_per_sec,
                      unsigned cpu_load, unsigned cpu_percent,
                      unsigned worker_index, int quiet)
{
    unsigned bytes = memory_kb * 1024U;
    unsigned char *buf;
    volatile unsigned acc = 0x13572468U ^ (worker_index * 0x01010101U);
    time_t start;
    time_t last_fork = 0;

    buf = malloc(bytes);
    if (!buf) {
        printf("kload: worker %u malloc %uKB failed (errno=%d)\n",
               worker_index, memory_kb, errno);
        return 1;
    }

    touch_memory(buf, bytes, 0x20U + worker_index);
    start = time(NULL);
    if (start == (time_t)-1)
        start = 0;

    if (!quiet) {
        printf("kload: pid=%d worker=%u seconds=%u memory=%uKB cpu=%u limit=%u%% forks/sec=%u\n",
               getpid(), worker_index, seconds, memory_kb, cpu_load, cpu_percent, forks_per_sec);
    }

    while (running) {
        time_t now = time(NULL);
        unsigned elapsed = (start && now != (time_t)-1) ? (unsigned)(now - start) : 0;
        unsigned long long active_start = now_us();
        unsigned long long active_end;

        for (unsigned i = 0; i < cpu_load && running; i++)
            cpu_burst(&acc);
        touch_memory(buf, bytes, acc);
        poke_procfs();

        if (forks_per_sec && now != last_fork) {
            for (unsigned i = 0; i < forks_per_sec && running; i++)
                fork_once(buf, bytes, acc + i);
            last_fork = now;
        }

        if (start && elapsed >= seconds)
            break;

        active_end = now_us();
        if (active_start && active_end > active_start)
            throttle_cpu(cpu_percent, active_end - active_start);
    }

    free(buf);
    if (!quiet)
        printf("kload: worker %u done acc=0x%08x\n", worker_index, (unsigned)acc);
    return 0;
}

static int run_workers(unsigned worker_count, unsigned seconds,
                       unsigned memory_kb, unsigned forks_per_sec,
                       unsigned cpu_load, unsigned cpu_percent, int quiet)
{
    int pids[MAX_WORKERS];
    int failures = 0;
    int launched = 0;
    int stop_sent = 0;

    for (unsigned i = 0; i < worker_count; i++)
        pids[i] = -1;

    if (!quiet) {
        printf("kload: parent pid=%d workers=%u seconds=%u memory=%uKB cpu=%u limit=%u%% each forks/sec=%u\n",
               getpid(), worker_count, seconds, memory_kb, cpu_load, cpu_percent, forks_per_sec);
    }

    for (unsigned i = 0; i < worker_count && running; i++) {
        int pid = fork();

        if (pid == 0)
            _exit(run_worker(seconds, memory_kb, forks_per_sec, cpu_load,
                             cpu_percent, i + 1U, 1));

        if (pid < 0) {
            printf("kload: fork worker %u failed (errno=%d)\n", i + 1U, errno);
            failures++;
            break;
        }

        pids[launched++] = pid;
    }

    while (launched > 0) {
        int status = 0;
        int pid = waitpid(-1, &status, 0);

        if (pid < 0) {
            if (errno == EINTR) {
                if (!running && !stop_sent) {
                    for (unsigned i = 0; i < worker_count; i++) {
                        if (pids[i] > 0)
                            kill(pids[i], SIGTERM);
                    }
                    stop_sent = 1;
                }
                continue;
            }
            break;
        }

        for (unsigned i = 0; i < worker_count; i++) {
            if (pids[i] == pid) {
                pids[i] = -1;
                break;
            }
        }

        launched--;
        if (status != 0)
            failures++;
    }

    if (!quiet || failures)
        printf("kload: parent done workers=%u failures=%d\n", worker_count, failures);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    unsigned seconds = DEFAULT_SECONDS;
    unsigned memory_kb = DEFAULT_MEMORY_KB;
    unsigned forks_per_sec = 0;
    unsigned cpu_load = 1;
    unsigned cpu_percent = MAX_CPU_PERCENT;
    unsigned worker_count = 1;
    int quiet;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            seconds = parse_uint_arg(argv[++i], DEFAULT_SECONDS);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            memory_kb = parse_uint_arg(argv[++i], DEFAULT_MEMORY_KB);
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cpu_load = parse_uint_arg(argv[++i], 1);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            cpu_percent = parse_uint_arg(argv[++i], MAX_CPU_PERCENT);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            forks_per_sec = parse_uint_arg(argv[++i], 0);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            worker_count = parse_uint_arg(argv[++i], 1);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (memory_kb > MAX_MEMORY_KB)
        memory_kb = MAX_MEMORY_KB;
    if (forks_per_sec > 8)
        forks_per_sec = 8;
    if (cpu_load < 1)
        cpu_load = 1;
    if (cpu_load > MAX_CPU_LOAD)
        cpu_load = MAX_CPU_LOAD;
    if (cpu_percent < 1)
        cpu_percent = 1;
    if (cpu_percent > MAX_CPU_PERCENT)
        cpu_percent = MAX_CPU_PERCENT;
    if (worker_count < 1)
        worker_count = 1;
    if (worker_count > MAX_WORKERS)
        worker_count = MAX_WORKERS;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    quiet = is_background_job();

    if (worker_count > 1)
        return run_workers(worker_count, seconds, memory_kb, forks_per_sec,
                           cpu_load, cpu_percent, quiet);

    return run_worker(seconds, memory_kb, forks_per_sec, cpu_load, cpu_percent, 1, quiet);
}

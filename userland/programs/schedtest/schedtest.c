/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/schedtest/schedtest.c
 * Layer: Userland / scheduler diagnostic
 * Description: Mixed CPU/sleep workload used to validate scheduler fairness.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_SECONDS     12U
#define DEFAULT_CPU_WORKERS 4U
#define DEFAULT_PROBES      2U
#define MAX_CHILDREN        32U
#define PROBE_SLEEP_US      100000U
#define PROBE_FAIL_US       2000000ULL
#define CPU_TIME_CHECK_MASK 0x0fU

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

static unsigned long long now_us(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return 0;

    return ((unsigned long long)tv.tv_sec * 1000000ULL) +
           (unsigned long long)tv.tv_usec;
}

static void usage(const char *prog)
{
    printf("usage: %s [-s seconds] [-c cpu_workers] [-p probes]\n", prog);
    printf("example: %s -s 20 -c 6 -p 2\n", prog);
}

static int cpu_worker(unsigned seconds, unsigned index)
{
    unsigned long long start = now_us();
    unsigned long long end = start + (unsigned long long)seconds * 1000000ULL;
    volatile unsigned acc = 0x12345678U ^ (index * 0x11111111U);
    unsigned long loops = 0;

    /*
     * Check wall-clock time only periodically. ArmOS still performs effective
     * userland preemption at kernel return points, so a rare gettimeofday()
     * keeps this as a scheduler stress test without flooding the kernel with
     * syscalls on every hot-loop iteration.
     */
    while (running) {
        for (unsigned batch = 0; batch < 64U; batch++) {
            for (unsigned i = 0; i < 1024U; i++) {
                acc ^= (acc << 5) + (acc >> 2) + i + batch;
                acc = (acc << 7) | (acc >> 25);
            }
        }
        loops++;
        if ((loops & CPU_TIME_CHECK_MASK) != 0)
            continue;
        if (now_us() >= end)
            break;
    }

    printf("schedtest: cpu worker %u done loops=%lu acc=0x%08x\n",
           index, loops, (unsigned)acc);
    return loops > 0 ? 0 : 1;
}

static int probe_worker(unsigned seconds, unsigned index)
{
    unsigned long long start = now_us();
    unsigned long long end = start + (unsigned long long)seconds * 1000000ULL;
    unsigned long long last = start;
    unsigned long long max_gap = 0;
    unsigned wakeups = 0;

    while (running && now_us() < end) {
        unsigned long long now;
        unsigned long long gap;

        usleep(PROBE_SLEEP_US);
        now = now_us();
        gap = now > last ? now - last : 0;
        if (gap > max_gap)
            max_gap = gap;
        last = now;
        wakeups++;
    }

    printf("schedtest: probe %u wakeups=%u max_gap=%luus\n",
           index, wakeups, (unsigned long)max_gap);

    if (wakeups == 0 || max_gap > PROBE_FAIL_US)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned seconds = DEFAULT_SECONDS;
    unsigned cpu_workers = DEFAULT_CPU_WORKERS;
    unsigned probes = DEFAULT_PROBES;
    int pids[MAX_CHILDREN];
    unsigned launched = 0;
    int failures = 0;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--seconds") == 0) && i + 1 < argc) {
            seconds = parse_uint_arg(argv[++i], DEFAULT_SECONDS);
        } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cpu") == 0) && i + 1 < argc) {
            cpu_workers = parse_uint_arg(argv[++i], DEFAULT_CPU_WORKERS);
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--probes") == 0) && i + 1 < argc) {
            probes = parse_uint_arg(argv[++i], DEFAULT_PROBES);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (cpu_workers + probes > MAX_CHILDREN) {
        printf("schedtest: too many children, max=%u\n", MAX_CHILDREN);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("schedtest: seconds=%u cpu_workers=%u probes=%u\n",
           seconds, cpu_workers, probes);
    printf("schedtest: probes fail if max wakeup gap exceeds %luus\n",
           (unsigned long)PROBE_FAIL_US);

    for (unsigned i = 0; i < cpu_workers; i++) {
        int pid = fork();
        if (pid == 0)
            _exit(cpu_worker(seconds, i + 1U));
        if (pid < 0) {
            printf("schedtest: fork cpu worker failed errno=%d\n", errno);
            failures++;
            break;
        }
        pids[launched++] = pid;
    }

    for (unsigned i = 0; i < probes; i++) {
        int pid = fork();
        if (pid == 0)
            _exit(probe_worker(seconds, i + 1U));
        if (pid < 0) {
            printf("schedtest: fork probe failed errno=%d\n", errno);
            failures++;
            break;
        }
        pids[launched++] = pid;
    }

    while (launched > 0) {
        int status = 0;
        int pid = waitpid(-1, &status, 0);

        if (pid < 0) {
            if (errno == EINTR)
                continue;
            printf("schedtest: waitpid failed errno=%d\n", errno);
            failures++;
            break;
        }

        (void)pids;
        launched--;
        if (status != 0)
            failures++;
    }

    if (failures) {
        printf("schedtest: failed (%d failure%s)\n",
               failures, failures == 1 ? "" : "s");
        return 1;
    }

    printf("schedtest: passed\n");
    return 0;
}

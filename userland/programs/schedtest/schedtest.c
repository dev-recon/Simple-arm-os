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
#include <fcntl.h>
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
#define SMP_MAX_CPUS        8U
#define SMP_PROC_BUF        4096
#define WNOHANG_BATCH        8U
#define WNOHANG_ROUNDS       16U
#define WNOHANG_POLL_US      1000U
#define WNOHANG_TIMEOUT_US   2000000ULL

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t interrupted_signal = 0;

typedef struct smp_sample {
    unsigned possible;
    unsigned sched_mask;
    unsigned timer[SMP_MAX_CPUS];
} smp_sample_t;

static void on_signal(int sig)
{
    interrupted_signal = sig;
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

static int read_file(const char *path, char *buf, int size)
{
    int fd;
    int n;

    if (!buf || size <= 1)
        return -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0)
        return -1;

    buf[n] = '\0';
    return n;
}

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

static int starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s++ != *prefix++)
            return 0;
    }
    return 1;
}

static int parse_smp_sample(smp_sample_t *sample)
{
    char buf[SMP_PROC_BUF];
    char *line;
    char *next;

    memset(sample, 0, sizeof(*sample));
    if (read_file("/proc/smp", buf, sizeof(buf)) < 0)
        return -1;

    line = buf;
    while (line && *line) {
        unsigned cpu, rq, irq, ipi, timer;
        char state[16], seen[8], sched[8];
        char *trimmed;

        next = strchr(line, '\n');
        if (next)
            *next++ = '\0';

        if (starts_with(line, "possible:")) {
            sample->possible = (unsigned)atoi(line + 9);
        } else {
            trimmed = (char *)skip_ws(line);
            if (*trimmed >= '0' && *trimmed <= '9') {
                /*
                 * /proc/smp is diagnostic text, not a stable binary ABI.
                 * Keep the parser intentionally narrow: we only need the CPU
                 * id, scheduler participation and per-CPU timer counter.
                 */
                if (sscanf(trimmed, "%u %15s %7s %7s %u %u %u %u",
                           &cpu, state, seen, sched, &rq, &irq, &ipi,
                           &timer) == 8 && cpu < SMP_MAX_CPUS) {
                    sample->timer[cpu] = timer;
                    if (strcmp(sched, "yes") == 0)
                        sample->sched_mask |= 1u << cpu;
                }
            }
        }

        line = next;
    }

    if (sample->possible > SMP_MAX_CPUS)
        sample->possible = SMP_MAX_CPUS;
    return sample->possible ? 0 : -1;
}

static int check_smp_timer_progress(const smp_sample_t *before,
                                    const smp_sample_t *after)
{
    unsigned checked = 0;
    unsigned failed = 0;
    unsigned mask = before->sched_mask & after->sched_mask;

    for (unsigned cpu = 0; cpu < after->possible && cpu < SMP_MAX_CPUS; cpu++) {
        unsigned delta;

        if ((mask & (1u << cpu)) == 0)
            continue;

        delta = after->timer[cpu] - before->timer[cpu];
        printf("schedtest: cpu%u timer delta=%u\n", cpu, delta);
        checked++;
        if (delta == 0)
            failed++;
    }

    if (checked < 2) {
        printf("schedtest: SMP check needs at least 2 schedulable CPUs\n");
        return 1;
    }

    if (failed) {
        printf("schedtest: %u schedulable CPU(s) did not tick\n", failed);
        return 1;
    }

    return 0;
}

static void usage(const char *prog)
{
    printf("usage: %s [-S|--smp] [-s seconds] [-c cpu_workers] [-p probes]\n", prog);
    printf("example: %s --smp\n", prog);
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

static int waitpid_wnohang_handoff_test(void)
{
    unsigned created = 0;

    for (unsigned round = 0; round < WNOHANG_ROUNDS; round++) {
        int pids[WNOHANG_BATCH];
        unsigned char reaped[WNOHANG_BATCH];
        unsigned launched = 0;
        unsigned remaining;
        unsigned long long deadline;

        memset(reaped, 0, sizeof(reaped));
        for (unsigned child = 0; child < WNOHANG_BATCH; child++) {
            int pid = fork();

            if (pid == 0)
                _exit((int)((round + child) & 0x7fU));
            if (pid < 0) {
                printf("schedtest: WNOHANG fork failed round=%u errno=%d\n",
                       round, errno);
                break;
            }

            pids[launched++] = pid;
            created++;
        }

        remaining = launched;
        deadline = now_us() + WNOHANG_TIMEOUT_US;
        while (remaining > 0 && now_us() < deadline) {
            for (unsigned child = 0; child < launched; child++) {
                int status = 0;
                int result;

                if (reaped[child])
                    continue;

                result = waitpid(pids[child], &status, WNOHANG);
                if (result == pids[child]) {
                    reaped[child] = 1;
                    remaining--;
                    if (!WIFEXITED(status) ||
                        WEXITSTATUS(status) !=
                            (int)((round + child) & 0x7fU)) {
                        printf("schedtest: WNOHANG bad status pid=%d status=%d\n",
                               result, status);
                        return 1;
                    }
                } else if (result < 0) {
                    printf("schedtest: WNOHANG wait failed pid=%d errno=%d\n",
                           pids[child], errno);
                    return 1;
                }
            }

            if (remaining > 0)
                usleep(WNOHANG_POLL_US);
        }

        if (remaining > 0) {
            printf("schedtest: WNOHANG timeout round=%u remaining=%u\n",
                   round, remaining);
            for (unsigned child = 0; child < launched; child++) {
                int status;

                if (!reaped[child])
                    waitpid(pids[child], &status, 0);
            }
            return 1;
        }

        if (launched != WNOHANG_BATCH)
            return 1;
    }

    printf("schedtest: WNOHANG handoff passed children=%u\n", created);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned seconds = DEFAULT_SECONDS;
    unsigned cpu_workers = DEFAULT_CPU_WORKERS;
    unsigned probes = DEFAULT_PROBES;
    int smp_mode = 0;
    int seconds_set = 0;
    int cpu_set = 0;
    int probes_set = 0;
    int pids[MAX_CHILDREN];
    unsigned launched = 0;
    int failures = 0;
    smp_sample_t smp_before;
    smp_sample_t smp_after;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--seconds") == 0) && i + 1 < argc) {
            seconds = parse_uint_arg(argv[++i], DEFAULT_SECONDS);
            seconds_set = 1;
        } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cpu") == 0) && i + 1 < argc) {
            cpu_workers = parse_uint_arg(argv[++i], DEFAULT_CPU_WORKERS);
            cpu_set = 1;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--probes") == 0) && i + 1 < argc) {
            probes = parse_uint_arg(argv[++i], DEFAULT_PROBES);
            probes_set = 1;
        } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--smp") == 0) {
            smp_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (smp_mode) {
        if (!seconds_set)
            seconds = 10;
        if (!cpu_set)
            cpu_workers = 8;
        if (!probes_set)
            probes = 4;
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

    if (smp_mode && parse_smp_sample(&smp_before) < 0) {
        printf("schedtest: cannot read /proc/smp\n");
        return 1;
    }

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
            if (errno == EINTR) {
                if (interrupted_signal)
                    break;
                continue;
            }
            printf("schedtest: waitpid failed errno=%d\n", errno);
            failures++;
            break;
        }

        (void)pids;
        launched--;
        if (status != 0)
            failures++;
    }

    if (interrupted_signal) {
        printf("schedtest: interrupted by signal %d\n", (int)interrupted_signal);
        return 128 + (int)interrupted_signal;
    }

    if (smp_mode) {
        if (parse_smp_sample(&smp_after) < 0) {
            printf("schedtest: cannot read /proc/smp after workload\n");
            failures++;
        } else if (check_smp_timer_progress(&smp_before, &smp_after) != 0) {
            failures++;
        }

        if (waitpid_wnohang_handoff_test() != 0)
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

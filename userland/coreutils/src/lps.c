/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/lps.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE_BUF_SIZE 4096
#define MAX_TASKS_VIEW 128
#define MAX_USERS_VIEW 16
#define USER_NAME_LEN 16

typedef struct user_entry {
    unsigned uid;
    char name[USER_NAME_LEN];
} user_entry_t;

typedef struct task_row {
    int pid;
    int tid;
    int ppid;
    int sid;
    int tty;
    unsigned uid;
    unsigned gid;
    unsigned priority;
    unsigned kstack_kb;
    unsigned heap_kb;
    unsigned vm_kb;
    unsigned rss_kb;
    unsigned l2_tables;
    unsigned switches;
    unsigned page_faults;
    unsigned cow_faults;
    unsigned stack_faults;
    unsigned lazy_faults;
    unsigned effective_priority;
    unsigned sched_debt;
    unsigned debt_score;
    unsigned ready_wait_ticks;
    int last_cpu;
    char state;
    char kind;
    char name[64];
} task_row_t;

typedef struct proc_counters {
    unsigned mem_total_kb;
    unsigned mem_free_kb;
    unsigned tasks_live, tasks_new, tasks_done;
    unsigned zombies_live, zombies_new, zombies_done;
    unsigned kstack_live, kstack_alloc, kstack_free;
    unsigned phys_live, phys_alloc, phys_free;
    unsigned forkfail;
    unsigned sched_refuse;
    unsigned sched_crit_repair;
    unsigned ready_refuse;
    unsigned asid_rollovers;
    unsigned state_set;
    unsigned signal_wake;
    unsigned tty_stale;
    unsigned fs_wait_timeout;
    unsigned sleep_deadline;
    unsigned sleep_overshoot;
    unsigned tty_tx_enqueued;
    unsigned tty_tx_drained;
    unsigned tty_tx_full_waits;
    unsigned tty_tx_drain_calls;
    unsigned tty_input_depth;
    unsigned tty_input_capacity;
    unsigned tty_eof_pending;
    unsigned tty_iflag;
    unsigned tty_oflag;
    unsigned tty_lflag;
    unsigned tty_vmin;
    unsigned tty_vtime;
    unsigned tty_char_wakeups;
    unsigned tty_line_wakeups;
    unsigned tty_eof_wakeups;
    unsigned sched_aging_selections;
    unsigned sched_debt_selections;
    unsigned sched_max_ready_debt;
    unsigned sched_avg_ready_debt;
    unsigned sched_last_tid;
    unsigned sched_last_pid;
    unsigned sched_last_prio;
    unsigned sched_last_effective;
    unsigned sched_last_debt;
    unsigned sched_last_waited;
    unsigned sched_last_scanned;
    char sched_last_reason[16];
} proc_counters_t;

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
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

static const char *parse_uint(const char *p, unsigned *out)
{
    unsigned value = 0;

    p = skip_ws(p);
    if (!is_digit(*p))
        return NULL;

    while (is_digit(*p)) {
        value = value * 10u + (unsigned)(*p - '0');
        p++;
    }

    *out = value;
    return p;
}

static const char *parse_int(const char *p, int *out)
{
    int sign = 1;
    unsigned value;

    p = skip_ws(p);
    if (*p == '-') {
        sign = -1;
        p++;
    }

    p = parse_uint(p, &value);
    if (!p)
        return NULL;

    *out = (int)value * sign;
    return p;
}

static int starts_with_key(const char *p, const char *key)
{
    while (*key) {
        if (*p++ != *key++)
            return 0;
    }
    return 1;
}

static const char *line_after_key(const char *buf, const char *key)
{
    int key_len = strlen(key);
    const char *p = buf;

    while (*p) {
        if (starts_with_key(p, key))
            return p + key_len;
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }

    return NULL;
}

static void parse_meminfo(proc_counters_t *c)
{
    char buf[FILE_BUF_SIZE];
    const char *p;

    if (read_file("/proc/meminfo", buf, sizeof(buf)) < 0)
        return;

    p = line_after_key(buf, "MemTotal:");
    if (p) parse_uint(p, &c->mem_total_kb);
    p = line_after_key(buf, "MemFree:");
    if (p) parse_uint(p, &c->mem_free_kb);
}

static void parse_proc_stat(proc_counters_t *c)
{
    char buf[FILE_BUF_SIZE];
    const char *p;

    if (read_file("/proc/stat", buf, sizeof(buf)) < 0)
        return;

    p = line_after_key(buf, "tasks ");
    if (p) {
        p = parse_uint(p, &c->tasks_live);
        if (p) p = parse_uint(p, &c->tasks_new);
        if (p) parse_uint(p, &c->tasks_done);
    }

    p = line_after_key(buf, "zombies ");
    if (p) {
        p = parse_uint(p, &c->zombies_live);
        if (p) p = parse_uint(p, &c->zombies_new);
        if (p) parse_uint(p, &c->zombies_done);
    }

    p = line_after_key(buf, "kstack ");
    if (p) {
        p = parse_uint(p, &c->kstack_live);
        if (p) p = parse_uint(p, &c->kstack_alloc);
        if (p) parse_uint(p, &c->kstack_free);
    }

    p = line_after_key(buf, "phys ");
    if (p) {
        p = parse_uint(p, &c->phys_live);
        if (p) p = parse_uint(p, &c->phys_alloc);
        if (p) parse_uint(p, &c->phys_free);
    }

    p = line_after_key(buf, "forkfail ");
    if (p) parse_uint(p, &c->forkfail);
    p = line_after_key(buf, "sched_refuse ");
    if (p) parse_uint(p, &c->sched_refuse);
    p = line_after_key(buf, "sched_crit_repair ");
    if (p) parse_uint(p, &c->sched_crit_repair);
    p = line_after_key(buf, "ready_refuse ");
    if (p) parse_uint(p, &c->ready_refuse);
    p = line_after_key(buf, "asid_rollovers ");
    if (p) parse_uint(p, &c->asid_rollovers);
    p = line_after_key(buf, "state_set ");
    if (p) parse_uint(p, &c->state_set);
    p = line_after_key(buf, "signal_wake ");
    if (p) parse_uint(p, &c->signal_wake);
    p = line_after_key(buf, "tty_stale ");
    if (p) parse_uint(p, &c->tty_stale);
    p = line_after_key(buf, "fs_wait_timeout ");
    if (p) parse_uint(p, &c->fs_wait_timeout);
    p = line_after_key(buf, "unintr_timeout ");
    if (p) parse_uint(p, &c->fs_wait_timeout);
    p = line_after_key(buf, "sleep_deadline ");
    if (p) parse_uint(p, &c->sleep_deadline);
    p = line_after_key(buf, "sleep_overshoot ");
    if (p) parse_uint(p, &c->sleep_overshoot);

    p = line_after_key(buf, "tty_tx ");
    if (p) {
        p = parse_uint(p, &c->tty_tx_enqueued);
        if (p) p = parse_uint(p, &c->tty_tx_drained);
        if (p) p = parse_uint(p, &c->tty_tx_full_waits);
        if (p) parse_uint(p, &c->tty_tx_drain_calls);
    }

    p = line_after_key(buf, "tty_in ");
    if (p) {
        p = parse_uint(p, &c->tty_input_depth);
        if (p) p = parse_uint(p, &c->tty_input_capacity);
        if (p) p = parse_uint(p, &c->tty_eof_pending);
        if (p) p = parse_uint(p, &c->tty_iflag);
        if (p) p = parse_uint(p, &c->tty_oflag);
        if (p) p = parse_uint(p, &c->tty_lflag);
        if (p) p = parse_uint(p, &c->tty_vmin);
        if (p) parse_uint(p, &c->tty_vtime);
    }

    p = line_after_key(buf, "tty_wake ");
    if (p) {
        p = parse_uint(p, &c->tty_char_wakeups);
        if (p) p = parse_uint(p, &c->tty_line_wakeups);
        if (p) parse_uint(p, &c->tty_eof_wakeups);
    }
}

static void parse_sched(proc_counters_t *c)
{
    char buf[FILE_BUF_SIZE];
    const char *p;

    if (read_file("/proc/sched", buf, sizeof(buf)) < 0)
        return;

    p = line_after_key(buf, "aging_selections ");
    if (p) parse_uint(p, &c->sched_aging_selections);
    p = line_after_key(buf, "debt_selections ");
    if (p) parse_uint(p, &c->sched_debt_selections);

    p = line_after_key(buf, "last_pick ");
    if (p) {
        const char *reason = strstr(p, "reason=");
        if (reason) {
            int len = 0;
            reason += 7;
            while (reason[len] && reason[len] != ' ' && reason[len] != '\n')
                len++;
            if (len >= (int)sizeof(c->sched_last_reason))
                len = (int)sizeof(c->sched_last_reason) - 1;
            memcpy(c->sched_last_reason, reason, (size_t)len);
            c->sched_last_reason[len] = '\0';
        }
        p = strstr(p, "tid=");
        if (p) parse_uint(p + 4, &c->sched_last_tid);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "pid=") : NULL;
        if (p) parse_uint(p + 4, &c->sched_last_pid);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "prio=") : NULL;
        if (p) parse_uint(p + 5, &c->sched_last_prio);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "effective=") : NULL;
        if (p) parse_uint(p + 10, &c->sched_last_effective);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "debt=") : NULL;
        if (p) parse_uint(p + 5, &c->sched_last_debt);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "waited=") : NULL;
        if (p) parse_uint(p + 7, &c->sched_last_waited);
        p = strstr(buf, "last_pick ");
        p = p ? strstr(p, "scanned=") : NULL;
        if (p) parse_uint(p + 8, &c->sched_last_scanned);
    }

    p = line_after_key(buf, "ready_debt ");
    if (p) {
        const char *maxp = strstr(p, "max=");
        const char *avgp = strstr(p, "avg=");
        if (maxp) parse_uint(maxp + 4, &c->sched_max_ready_debt);
        if (avgp) parse_uint(avgp + 4, &c->sched_avg_ready_debt);
    }
}

static void parse_passwd(user_entry_t *users, int *count)
{
    char buf[FILE_BUF_SIZE];
    const char *p;

    *count = 0;
    if (read_file("/etc/passwd", buf, sizeof(buf)) < 0)
        return;

    p = buf;
    while (*p && *count < MAX_USERS_VIEW) {
        const char *name_start = p;
        const char *uid_start;
        int name_len;
        unsigned uid;

        while (*p && *p != ':' && *p != '\n')
            p++;
        if (*p != ':')
            goto next_line;

        name_len = (int)(p - name_start);
        p++; /* password */
        while (*p && *p != ':' && *p != '\n')
            p++;
        if (*p != ':')
            goto next_line;
        p++;

        uid_start = p;
        if (!parse_uint(uid_start, &uid))
            goto next_line;

        if (name_len >= USER_NAME_LEN)
            name_len = USER_NAME_LEN - 1;
        memcpy(users[*count].name, name_start, (size_t)name_len);
        users[*count].name[name_len] = '\0';
        users[*count].uid = uid;
        (*count)++;

next_line:
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }
}

static const char *user_name_for_uid(user_entry_t *users, int count, unsigned uid,
                                     char *fallback, int fallback_size)
{
    for (int i = 0; i < count; i++) {
        if (users[i].uid == uid)
            return users[i].name;
    }

    snprintf(fallback, fallback_size, "%u", uid);
    return fallback;
}

static void parse_tasks(task_row_t *rows, int *count)
{
    char buf[FILE_BUF_SIZE];
    const char *p;

    *count = 0;
    if (read_file("/proc/tasks", buf, sizeof(buf)) < 0)
        return;

    p = buf;
    while (*p && *p != '\n')
        p++;
    if (*p == '\n')
        p++;

    while (*p && *count < MAX_TASKS_VIEW) {
        task_row_t *r = &rows[*count];
        const char *name_start;
        int len = 0;

        memset(r, 0, sizeof(*r));
        r->tty = -1;
        r->last_cpu = -1;
        r->priority = 10;
        r->kstack_kb = 16;

        p = parse_int(p, &r->pid);
        if (!p) break;
        p = parse_int(p, &r->tid);
        if (!p) break;
        p = parse_int(p, &r->ppid);
        if (!p) break;
        p = skip_ws(p);
        r->state = *p ? *p++ : 'S';
        p = skip_ws(p);
        r->kind = *p ? *p++ : 'K';
        p = parse_uint(p, &r->priority);
        if (!p) break;
        p = parse_uint(p, &r->switches);
        if (!p) break;
        p = parse_uint(p, &r->page_faults);
        if (!p) break;
        p = parse_uint(p, &r->cow_faults);
        if (!p) break;
        p = parse_uint(p, &r->stack_faults);
        if (!p) break;
        p = skip_ws(p);
        name_start = p;
        while (*p && *p != '\n')
            p++;
        len = (int)(p - name_start);
        if (len >= (int)sizeof(r->name))
            len = (int)sizeof(r->name) - 1;
        memcpy(r->name, name_start, (size_t)len);
        r->name[len] = '\0';
        if (*p == '\n')
            p++;
        (*count)++;
    }
}

static void status_string_value(const char *buf, const char *key, char *out, int size)
{
    const char *p = line_after_key(buf, key);
    int len = 0;

    if (!p || size <= 0)
        return;

    p = skip_ws(p);
    while (p[len] && p[len] != '\n')
        len++;
    if (len >= size)
        len = size - 1;
    memcpy(out, p, (size_t)len);
    out[len] = '\0';
}

static void status_uint_value(const char *buf, const char *key, unsigned *out)
{
    const char *p = line_after_key(buf, key);
    if (p)
        parse_uint(p, out);
}

static void status_int_value(const char *buf, const char *key, int *out)
{
    const char *p = line_after_key(buf, key);
    if (p)
        parse_int(p, out);
}

static void enrich_row_from_status(task_row_t *r)
{
    char path[64];
    char buf[FILE_BUF_SIZE];
    char state_text[64] = {0};

    if (r->pid <= 0)
        return;

    sprintf(path, "/proc/%d/status", r->pid);
    if (read_file(path, buf, sizeof(buf)) < 0)
        return;

    status_string_value(buf, "Name:", r->name, sizeof(r->name));
    status_string_value(buf, "State:", state_text, sizeof(state_text));
    if (state_text[0])
        r->state = state_text[0];
    status_int_value(buf, "Pid:", &r->pid);
    status_int_value(buf, "Tid:", &r->tid);
    status_int_value(buf, "PPid:", &r->ppid);
    status_int_value(buf, "Sid:", &r->sid);
    status_int_value(buf, "Tty:", &r->tty);
    status_uint_value(buf, "Uid:", &r->uid);
    status_uint_value(buf, "Gid:", &r->gid);
    status_uint_value(buf, "Priority:", &r->priority);
    status_uint_value(buf, "EffectivePriority:", &r->effective_priority);
    status_uint_value(buf, "SchedDebt:", &r->sched_debt);
    status_uint_value(buf, "DebtScore:", &r->debt_score);
    status_uint_value(buf, "ReadyWaitTicks:", &r->ready_wait_ticks);
    status_int_value(buf, "CPU:", &r->last_cpu);
    status_uint_value(buf, "KStack:", &r->kstack_kb);
    status_uint_value(buf, "Heap:", &r->heap_kb);
    status_uint_value(buf, "VmSize:", &r->vm_kb);
    status_uint_value(buf, "VmRSS:", &r->rss_kb);
    status_uint_value(buf, "L2Tables:", &r->l2_tables);
    status_uint_value(buf, "CtxSwitches:", &r->switches);
    status_uint_value(buf, "PageFaults:", &r->page_faults);
    status_uint_value(buf, "CowFaults:", &r->cow_faults);
    status_uint_value(buf, "StackFaults:", &r->stack_faults);
    status_uint_value(buf, "LazyFaults:", &r->lazy_faults);
}

static const char *state_name(char state)
{
    switch (state) {
        case 'R': return "run";
        case 'Z': return "zombie";
        case 'T': return "term";
        case 't': return "stop";
        case 'D': return "wait";
        default:  return "sleep";
    }
}

static const char *state_color(char state)
{
    switch (state) {
        case 'R': return "\033[1;32m";
        case 'Z': return "\033[1;31m";
        case 'T': return "\033[0;31m";
        case 't': return "\033[1;33m";
        case 'D': return "\033[1;33m";
        default:  return "\033[36m";
    }
}

static const char *kind_name(char type)
{
    switch (type) {
        case 'P': return "proc";
        case 'T': return "thread";
        default:  return "kthr";
    }
}

static const char *kind_color(char type)
{
    switch (type) {
        case 'P': return "\033[1;36m";
        case 'T': return "\033[1;35m";
        default:  return "\033[0;36m";
    }
}

static void format_count(unsigned value, char *buf, int size)
{
    if (value >= 1000000u) {
        unsigned whole = value / 1000000u;
        unsigned dec = (value % 1000000u) / 100000u;
        if (dec)
            snprintf(buf, (size_t)size, "%u.%uM", whole, dec);
        else
            snprintf(buf, (size_t)size, "%uM", whole);
    } else if (value >= 1000u) {
        unsigned whole = value / 1000u;
        unsigned dec = (value % 1000u) / 100u;
        if (dec)
            snprintf(buf, (size_t)size, "%u.%uK", whole, dec);
        else
            snprintf(buf, (size_t)size, "%uK", whole);
    } else {
        snprintf(buf, (size_t)size, "%u", value);
    }
}

static void print_lifecycle_table(const proc_counters_t *c)
{
    printf("\033[1m%-7s %-10s %10s %10s %10s\033[0m\n",
           "GROUP", "METRIC", "LIVE", "+NEW", "-DONE");
    printf("%-7s %-10s %10u %10u %10u\n",
           "life", "tasks", c->tasks_live, c->tasks_new, c->tasks_done);
    printf("%-7s %-10s %10u %10u %10u\n",
           "life", "zombies", c->zombies_live, c->zombies_new, c->zombies_done);
    printf("%-7s %-10s %9up %9up %9up\n",
           "alloc", "kstack", c->kstack_live, c->kstack_alloc, c->kstack_free);
    printf("%-7s %-10s %9up %9up %9up\n",
           "alloc", "phys", c->phys_live, c->phys_alloc, c->phys_free);
}

static void print_event_table(const proc_counters_t *c)
{
    printf("\n\033[1m%-16s %8s   %-16s %8s   %-16s %8s\033[0m\n",
           "EVENT", "VALUE", "EVENT", "VALUE", "EVENT", "VALUE");
    printf("%-16s %8u   %-16s %8u   %-16s %8u\n",
           "forkfail", c->forkfail,
           "sched-refuse", c->sched_refuse,
           "ready-refuse", c->ready_refuse);
    printf("%-16s %8u   %-16s %8u   %-16s %8u\n",
           "asid-roll", c->asid_rollovers,
           "sched-crit", c->sched_crit_repair,
           "signal-wake", c->signal_wake);
    printf("%-16s %8u   %-16s %8u   %-16s %8u\n",
           "state-set", c->state_set,
           "tty-stale", c->tty_stale,
           "fs-wait-timeout", c->fs_wait_timeout);
    printf("%-16s %8u   %-16s %8u   %-16s %8s\n",
           "sleep-deadline", c->sleep_deadline,
           "sleep-overshoot", c->sleep_overshoot,
           "", "");
}

static void print_scheduler_table(const proc_counters_t *c)
{
    printf("\n\033[1mScheduler\033[0m  policy=priority-rr-debt\n");
    printf("  \033[1m%-16s %8s   %-16s %8s   %-16s %8s\033[0m\n",
           "metric", "value", "metric", "value", "metric", "value");
    printf("  %-16s %8u   %-16s %8u   %-16s %8u\n",
           "aging-picks", c->sched_aging_selections,
           "debt-picks", c->sched_debt_selections,
           "scan-last", c->sched_last_scanned);
    printf("  %-16s %8u   %-16s %8u   %-16s %8s\n",
           "ready-max-debt", c->sched_max_ready_debt,
           "ready-avg-debt", c->sched_avg_ready_debt,
           "last-reason", c->sched_last_reason[0] ? c->sched_last_reason : "-");
    printf("  last-pick pid=%u tid=%u prio=%u effective=%u debt=%u waited=%u\n",
           c->sched_last_pid,
           c->sched_last_tid,
           c->sched_last_prio,
           c->sched_last_effective,
           c->sched_last_debt,
           c->sched_last_waited);
}

static void print_tty_table(const proc_counters_t *c)
{
    printf("\n\033[1mTTY summary\033[0m  (per-tty details: /proc/tty)\n");
    printf("  \033[1m%-8s %12s %12s %12s %12s\033[0m\n",
           "output", "enqueued", "drained", "full-wait", "drain-call");
    printf("  %-8s %12u %12u %12u %12u\n",
           "",
           c->tty_tx_enqueued,
           c->tty_tx_drained,
           c->tty_tx_full_waits,
           c->tty_tx_drain_calls);
    printf("  \033[1m%-8s %12s %12s %12s %12s %12s\033[0m\n",
           "input", "depth", "capacity", "eof", "vmin", "vtime");
    printf("  %-8s %12u %12u %12u %12u %12u\n",
           "",
           c->tty_input_depth,
           c->tty_input_capacity,
           c->tty_eof_pending,
           c->tty_vmin,
           c->tty_vtime);
    printf("  \033[1m%-8s %12s %12s %12s\033[0m\n",
           "flags", "iflag", "oflag", "lflag");
    printf("  %-8s %12u %12u %12u\n",
           "",
           c->tty_iflag,
           c->tty_oflag,
           c->tty_lflag);
    printf("  \033[1m%-8s %12s %12s %12s\033[0m\n",
           "wakeups", "char", "line", "eof");
    printf("  %-8s %12u %12u %12u\n\n",
           "",
           c->tty_char_wakeups,
           c->tty_line_wakeups,
           c->tty_eof_wakeups);
}

int main(void)
{
    proc_counters_t c;
    task_row_t rows[MAX_TASKS_VIEW];
    user_entry_t users[MAX_USERS_VIEW];
    int count = 0;
    int user_count = 0;
    unsigned used_kb;
    unsigned pct_x10;

    memset(&c, 0, sizeof(c));
    memset(rows, 0, sizeof(rows));

    parse_meminfo(&c);
    parse_proc_stat(&c);
    parse_sched(&c);
    parse_passwd(users, &user_count);
    parse_tasks(rows, &count);
    for (int i = 0; i < count; i++) {
        rows[i].effective_priority = rows[i].priority;
        enrich_row_from_status(&rows[i]);
    }

    used_kb = c.mem_total_kb >= c.mem_free_kb ? c.mem_total_kb - c.mem_free_kb : 0;
    pct_x10 = c.mem_total_kb ? (used_kb * 1000u / c.mem_total_kb) : 0;

    printf("\033[1mMem:\033[0m  %u MB total   %u MB free   \033[%sm%u.%u%%\033[0m used\n\n",
           c.mem_total_kb / 1024u, c.mem_free_kb / 1024u,
           pct_x10 > 800 ? "1;31" : pct_x10 > 600 ? "1;33" : "1;32",
           pct_x10 / 10u, pct_x10 % 10u);

    print_lifecycle_table(&c);
    print_event_table(&c);
    print_scheduler_table(&c);
    print_tty_table(&c);

    printf("\033[1m%6s %6s %6s %4s %3s %-8s %4s %-6s %3s %4s %6s %6s %5s %5s %5s %5s %2s %7s %7s %7s %7s %7s %-6s %4s %s\033[0m\n",
           "PID", "TID", "PPID", "SID", "TTY", "USER", "GID", "KIND", "PRI", "%CPU", "KSTK", "HEAP",
           "DEBT", "WAIT", "VM", "RSS", "L2", "CTX", "PF", "COW", "STK", "LZY", "STATE", "LAST", "NAME");
    printf("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < count; i++) {
        task_row_t *p = &rows[i];
        const char *pfcolor = p->page_faults ? "\033[1;35m" : "\033[0m";
        char ctxbuf[16];
        char pfbuf[16];
        char cowbuf[16];
        char stkbuf[16];
        char lazybuf[16];
        char user_fallback[USER_NAME_LEN];
        const char *user = user_name_for_uid(users, user_count, p->uid,
                                             user_fallback, sizeof(user_fallback));

        format_count(p->switches, ctxbuf, sizeof(ctxbuf));
        format_count(p->page_faults, pfbuf, sizeof(pfbuf));
        format_count(p->cow_faults, cowbuf, sizeof(cowbuf));
        format_count(p->stack_faults, stkbuf, sizeof(stkbuf));
        format_count(p->lazy_faults, lazybuf, sizeof(lazybuf));

        printf("%6d %6d %6d %4d %3d %-8s %4u %s%-6s\033[0m %3u %3u.%u %4uK %4uK %5u %5u %4uK %4uK %2u %7s %s%7s\033[0m %7s %7s %7s %s%-6s\033[0m %4d %s\n",
               p->pid, p->tid, p->ppid, p->sid, p->tty,
               user, p->gid,
               kind_color(p->kind), kind_name(p->kind),
               p->priority,
               0u, 0u,
               p->kstack_kb, p->heap_kb,
               p->debt_score, p->ready_wait_ticks,
               p->vm_kb, p->rss_kb,
               p->l2_tables,
               ctxbuf,
               pfcolor, pfbuf,
               cowbuf, stkbuf, lazybuf,
               state_color(p->state), state_name(p->state),
               p->last_cpu,
               p->name);
    }

    return 0;
}

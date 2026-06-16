#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
        default:  return "\033[0;37m";
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

int main(void)
{
    struct sysinfo_response *info = malloc(sizeof(struct sysinfo_response));
    if (!info) { printf("ps: out of memory\n"); return 1; }

    int n = getsysinfo(info);
    if (n < 0) {
        printf("ps: getsysinfo failed\n");
        free(info);
        return 1;
    }

    /* Ligne mémoire */
    unsigned used_kb = info->mem_total_kb - info->mem_free_kb;
    unsigned pct_x10 = info->mem_total_kb ? (used_kb * 1000 / info->mem_total_kb) : 0;
    unsigned pct = pct_x10 / 10;
    unsigned pct_frac = pct_x10 % 10;
    unsigned live_tasks = info->tasks_created >= info->tasks_destroyed
                        ? info->tasks_created - info->tasks_destroyed : 0;
    unsigned live_zombies = info->zombies_created >= info->zombies_reaped
                          ? info->zombies_created - info->zombies_reaped : 0;
    unsigned live_kstack_pages = info->stack_pages_allocated >= info->stack_pages_freed
                               ? info->stack_pages_allocated - info->stack_pages_freed : 0;
    unsigned live_phys_pages = info->phys_pages_allocated >= info->phys_pages_freed
                             ? info->phys_pages_allocated - info->phys_pages_freed : 0;
    printf("\033[1mMem:\033[0m  %u MB total   %u MB free   \033[%sm%u.%u%%\033[0m used\n\n",
           info->mem_total_kb / 1024, info->mem_free_kb / 1024,
           pct_x10 > 800 ? "1;31" : pct_x10 > 600 ? "1;33" : "1;32",
           pct, pct_frac);
    printf("\033[1m%-6s\033[0m %-10s %8s %8s %8s   %-12s %u  %-12s %u  %-12s %u\n",
           "Life:", "metric", "live", "+new", "-done",
           "forkfail", info->failed_forks,
           "sched-refuse", info->scheduler_refused,
           "ready-refuse", info->ready_queue_refused);
    printf("%-6s %-10s %8u %8u %8u   %-12s %u\n",
           "", "tasks",
           live_tasks, info->tasks_created, info->tasks_destroyed,
           "asid-roll", info->asid_rollovers);
    printf("%-6s %-10s %8u %8u %8u\n",
           "", "zombies",
           live_zombies, info->zombies_created, info->zombies_reaped);

    printf("\033[1m%-6s\033[0m %-10s %8s %8s %8s\n",
           "Alloc:", "metric", "live", "+alloc", "-free");
    printf("%-6s %-10s %7up %7up %7up\n",
           "", "kstack",
           live_kstack_pages,
           info->stack_pages_allocated, info->stack_pages_freed);
    printf("%-6s %-10s %7up %7up %7up\n",
           "", "phys",
           live_phys_pages,
           info->phys_pages_allocated, info->phys_pages_freed);

    printf("\033[1m%-6s\033[0m %-12s %7u   %-12s %7u   %-12s %7u   %-12s %7u\n\n",
           "Diag:",
           "state-set", info->state_sync_repairs,
           "signal-wake", info->blocked_signal_wakeups,
           "tty-stale", info->tty_stale_waiters,
           "unintr-timeout", info->uninterruptible_timeouts);

    /* Header */
    printf("\033[1m%4s %4s %4s %4s %3s %-6s %3s %5s %5s %5s %5s %5s %2s %5s %4s %4s %4s %-6s %s\033[0m\n",
           "PID", "TID", "PPID", "SID", "TTY", "KIND", "PRI", "%CPU", "KSTK", "HEAP",
           "VM", "RSS", "L2", "CTX", "PF", "COW", "STK", "STATE", "NAME");
    printf("----------------------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < n; i++) {
        struct proc_info *p = &info->procs[i];

        unsigned ci = p->cpu_pct_x10 / 10;
        unsigned cf = p->cpu_pct_x10 % 10;
        const char *cpucolor = ci >= 50 ? "\033[1;31m" :
                               ci >= 20 ? "\033[1;33m" : "\033[0m";
        const char *pfcolor = p->page_faults ? "\033[1;35m" : "\033[0m";

        printf("%4u %4d %4d %4d %3d %s%-6s\033[0m %3u %s%3u.%u\033[0m %4uK %4uK %4uK %4uK %2u %5u %s%4u\033[0m %4u %4u %s%-6s\033[0m %s\n",
               p->pid, p->tid, p->ppid, p->sid, p->tty,
               kind_color(p->type), kind_name(p->type),
               p->priority,
               cpucolor, ci, cf,
               p->stack_kb, p->heap_kb, p->vm_kb, p->rss_kb,
               p->l2_tables,
               p->switches,
               pfcolor, p->page_faults,
               p->cow_faults, p->stack_faults,
               state_color(p->state), state_name(p->state),
               p->name);
    }

    free(info);
    return 0;
}

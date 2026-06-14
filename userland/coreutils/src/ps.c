#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
    unsigned pct = info->mem_total_kb ? (used_kb * 100 / info->mem_total_kb) : 0;
    printf("\033[1mMem:\033[0m  %u MB total   %u MB free   \033[%sm%u%%\033[0m used\n\n",
           info->mem_total_kb / 1024, info->mem_free_kb / 1024,
           pct > 80 ? "1;31" : pct > 60 ? "1;33" : "1;32", pct);

    /* Header */
    printf("\033[1m%5s %5s %4s %6s %7s %7s %6s  %-8s  %s\033[0m\n",
           "PID", "PPID", "PRI", "%CPU", "STACK", "HEAP", "CTXSW", "STATE", "NAME");
    printf("----------------------------------------------------------------\n");

    for (int i = 0; i < n; i++) {
        struct proc_info *p = &info->procs[i];

        const char *color, *sstr;
        switch (p->state) {
            case 'R': color = "\033[1;32m"; sstr = "running"; break;
            case 'Z': color = "\033[1;31m"; sstr = "zombie";  break;
            case 'T': color = "\033[0;31m"; sstr = "term";    break;
            case 'D': color = "\033[1;33m"; sstr = "wait";    break;
            default:  color = "\033[0;37m"; sstr = "sleep";   break;
        }

        unsigned ci = p->cpu_pct_x10 / 10;
        unsigned cf = p->cpu_pct_x10 % 10;
        const char *cpucolor = ci >= 50 ? "\033[1;31m" :
                               ci >= 20 ? "\033[1;33m" : "\033[0m";

        printf("%5d %5d %4u %s%3u.%u%%\033[0m %5uKB %5uKB %6u  %s%-8s\033[0m  %s\n",
               p->pid, p->ppid, p->priority,
               cpucolor, ci, cf,
               p->stack_kb, p->heap_kb,
               p->switches,
               color, sstr,
               p->name);
    }

    free(info);
    return 0;
}

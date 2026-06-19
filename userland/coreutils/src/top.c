#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TOP_PROC_BUF 4096
#define TOP_MAX_TASKS 128
#define TOP_HZ 1000

#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_GREEN   "\033[32m"
#define C_YELLOW  "\033[33m"
#define C_BLUE    "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN    "\033[36m"
#define C_RED     "\033[31m"

typedef struct top_task {
    int pid;
    int tty;
    unsigned runtime_ticks;
    unsigned ctx;
    unsigned pf;
    unsigned rss_kb;
    char state;
    char name[64];
} top_task_t;

typedef struct top_mem {
    unsigned total_kb;
    unsigned free_kb;
} top_mem_t;

static volatile sig_atomic_t top_running = 1;
static top_task_t top_tasks[TOP_MAX_TASKS];

static void on_signal(int sig)
{
    (void)sig;
    top_running = 0;
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
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
    unsigned value = 0;

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
    const char *p = buf;

    while (*p) {
        if (starts_with_key(p, key))
            return p + strlen(key);
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }

    return NULL;
}

static void read_mem(top_mem_t *mem)
{
    char buf[1024];
    const char *p;

    memset(mem, 0, sizeof(*mem));
    if (read_file("/proc/meminfo", buf, sizeof(buf)) < 0)
        return;

    p = line_after_key(buf, "MemTotal:");
    if (p)
        parse_uint(p, &mem->total_kb);
    p = line_after_key(buf, "MemFree:");
    if (p)
        parse_uint(p, &mem->free_kb);
}

static int parse_proc_stat(const char *buf, top_task_t *task)
{
    const char *p;
    const char *start;
    const char *end;
    int dummy;
    unsigned udummy;
    int len;

    p = parse_int(buf, &task->pid);
    if (!p)
        return -1;

    p = skip_ws(p);
    if (*p != '(')
        return -1;

    start = ++p;
    end = start;
    while (*end && *end != ')')
        end++;
    if (*end != ')')
        return -1;

    len = (int)(end - start);
    if (len >= (int)sizeof(task->name))
        len = (int)sizeof(task->name) - 1;
    memcpy(task->name, start, (size_t)len);
    task->name[len] = '\0';

    p = skip_ws(end + 1);
    task->state = *p ? *p++ : 'S';

    p = parse_int(p, &dummy);       /* ppid */
    if (!p) return -1;
    p = parse_int(p, &dummy);       /* pgid */
    if (!p) return -1;
    p = parse_int(p, &dummy);       /* sid */
    if (!p) return -1;
    p = parse_int(p, &task->tty);
    if (!p) return -1;
    p = parse_uint(p, &task->pf);
    if (!p) return 0;
    p = parse_uint(p, &udummy);     /* cow faults */
    if (!p) return 0;
    p = parse_uint(p, &udummy);     /* stack faults */
    if (!p) return 0;
    p = parse_uint(p, &task->ctx);
    if (!p) return 0;
    p = parse_uint(p, &task->runtime_ticks);

    return 0;
}

static void enrich_from_status(top_task_t *task)
{
    char path[64];
    char buf[1024];
    const char *p;

    if (task->pid <= 0)
        return;

    sprintf(path, "/proc/%d/status", task->pid);
    if (read_file(path, buf, sizeof(buf)) < 0)
        return;

    p = line_after_key(buf, "VmRSS:");
    if (p)
        parse_uint(p, &task->rss_kb);
}

static int load_tasks(top_task_t *tasks, int max_tasks)
{
    char *dirbuf;
    char statbuf[512];
    int fd;
    int n;
    int count = 0;

    dirbuf = malloc(TOP_PROC_BUF);
    if (!dirbuf)
        return 0;

    fd = open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        free(dirbuf);
        return 0;
    }

    while ((n = getdents(fd, dirbuf, TOP_PROC_BUF)) > 0 && count < max_tasks) {
        char *ptr = dirbuf;

        while (ptr < dirbuf + n && count < max_tasks) {
            struct linux_dirent *e = (struct linux_dirent *)ptr;
            char path[64];

            if (e->d_reclen == 0)
                break;

            if (e->d_ino != 0 && is_digit(e->d_name[0])) {
                memset(&tasks[count], 0, sizeof(tasks[count]));
                tasks[count].tty = -1;
                sprintf(path, "/proc/%s/stat", e->d_name);
                if (read_file(path, statbuf, sizeof(statbuf)) >= 0 &&
                    parse_proc_stat(statbuf, &tasks[count]) == 0) {
                    enrich_from_status(&tasks[count]);
                    count++;
                }
            }

            ptr += e->d_reclen;
        }
    }

    close(fd);
    free(dirbuf);
    return count;
}

static int compare_tasks(const void *a, const void *b)
{
    const top_task_t *ta = (const top_task_t *)a;
    const top_task_t *tb = (const top_task_t *)b;

    if (tb->runtime_ticks != ta->runtime_ticks)
        return tb->runtime_ticks > ta->runtime_ticks ? 1 : -1;
    if (tb->ctx != ta->ctx)
        return tb->ctx > ta->ctx ? 1 : -1;
    return ta->pid - tb->pid;
}

static void format_runtime(unsigned ticks, char *buf, int size)
{
    unsigned centis = (ticks * 100u) / TOP_HZ;
    unsigned minutes = centis / 6000u;
    unsigned seconds = (centis / 100u) % 60u;
    unsigned hundredths = centis % 100u;

    snprintf(buf, (size_t)size, "%u:%02u.%02u", minutes, seconds, hundredths);
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
    case 'R': return C_GREEN;
    case 'Z': return C_RED;
    case 'T':
    case 't': return C_YELLOW;
    case 'D': return C_MAGENTA;
    default:  return C_BLUE;
    }
}

static void print_tty(int tty)
{
    if (tty >= 0)
        printf("tty%d", tty);
    else
        printf("?");
}

static void render_top(unsigned delay_sec, int iteration)
{
    top_mem_t mem;
    unsigned used_kb;
    unsigned pct_x10;
    int count;

    read_mem(&mem);
    count = load_tasks(top_tasks, TOP_MAX_TASKS);
    qsort(top_tasks, (size_t)count, sizeof(top_tasks[0]), compare_tasks);

    used_kb = mem.total_kb >= mem.free_kb ? mem.total_kb - mem.free_kb : 0;
    pct_x10 = mem.total_kb ? (used_kb * 1000u / mem.total_kb) : 0;

    printf("\033[H\033[2J\033[3J");
    printf(C_BOLD C_CYAN "ArmOS top" C_RESET " - refresh %us", delay_sec);
    if (iteration >= 0)
        printf(" - iteration %d", iteration + 1);
    printf(" - " C_DIM "Ctrl-C to quit" C_RESET "\n");
    printf(C_BOLD "Mem:" C_RESET " %uM total, " C_GREEN "%uM free" C_RESET
           ", " C_YELLOW "%u.%u%% used" C_RESET ", tasks: %d\n\n",
           mem.total_kb / 1024u,
           mem.free_kb / 1024u,
           pct_x10 / 10u,
           pct_x10 % 10u,
           count);

    printf(C_BOLD "%5s %-8s %-8s %8s %8s %6s %6s %s" C_RESET "\n",
           "PID", "TTY", "STATE", "TIME", "CTX", "PF", "RSS", "CMD");
    printf(C_DIM "----------------------------------------------------------------" C_RESET "\n");

    for (int i = 0; i < count; i++) {
        char timebuf[16];
        const char *color = state_color(top_tasks[i].state);

        format_runtime(top_tasks[i].runtime_ticks, timebuf, sizeof(timebuf));
        printf(C_CYAN "%5d" C_RESET " ", top_tasks[i].pid);
        print_tty(top_tasks[i].tty);
        printf("%*s %s%-8s" C_RESET " %8s %8u %6u %5uK %s\n",
               top_tasks[i].tty >= 0 ? 4 : 7,
               "",
               color,
               state_name(top_tasks[i].state),
               timebuf,
               top_tasks[i].ctx,
               top_tasks[i].pf,
               top_tasks[i].rss_kb,
               top_tasks[i].name);
    }

    fflush(stdout);
}

static void top_delay(unsigned delay_sec)
{
    unsigned slices = delay_sec * 10U;

    for (unsigned i = 0; top_running && i < slices; i++)
        usleep(100000);
}

static int parse_args(int argc, char **argv, unsigned *delay_sec, int *count)
{
    *delay_sec = 2;
    *count = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            int value = atoi(argv[++i]);
            if (value <= 0)
                return -1;
            *delay_sec = (unsigned)value;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            int value = atoi(argv[++i]);
            if (value <= 0)
                return -1;
            *count = value;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            return 1;
        } else {
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    unsigned delay_sec;
    int max_count;
    int parsed;
    int iteration = 0;

    parsed = parse_args(argc, argv, &delay_sec, &max_count);
    if (parsed != 0) {
        printf("usage: top [-s seconds] [-n count]\n");
        return parsed < 0 ? 1 : 0;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    while (top_running && (max_count < 0 || iteration < max_count)) {
        render_top(delay_sec, max_count >= 0 ? iteration : -1);
        iteration++;
        if (!top_running || (max_count >= 0 && iteration >= max_count))
            break;
        top_delay(delay_sec);
    }

    printf(C_RESET "\n");
    return 0;
}

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE          4096U
#define DEFAULT_SECONDS    60U
#define DEFAULT_MEMORY_KB  1024U
#define MAX_MEMORY_KB      8192U
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
    printf("usage: %s [-s seconds] [-m memory_kb] [-f forks_per_sec]\n", prog);
    printf("example: %s -s 120 -m 4096 -f 1 &\n", prog);
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

int main(int argc, char **argv)
{
    unsigned seconds = DEFAULT_SECONDS;
    unsigned memory_kb = DEFAULT_MEMORY_KB;
    unsigned forks_per_sec = 0;
    unsigned bytes;
    unsigned char *buf;
    volatile unsigned acc = 0x13572468U;
    time_t start;
    time_t last_fork = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            seconds = parse_uint_arg(argv[++i], DEFAULT_SECONDS);
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            memory_kb = parse_uint_arg(argv[++i], DEFAULT_MEMORY_KB);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            forks_per_sec = parse_uint_arg(argv[++i], 0);
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

    bytes = memory_kb * 1024U;
    buf = malloc(bytes);
    if (!buf) {
        printf("kload: malloc %uKB failed (errno=%d)\n", memory_kb, errno);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    touch_memory(buf, bytes, 0x20U);
    start = time(NULL);
    if (start == (time_t)-1)
        start = 0;

    printf("kload: pid=%d seconds=%u memory=%uKB forks/sec=%u\n",
           getpid(), seconds, memory_kb, forks_per_sec);

    while (running) {
        time_t now = time(NULL);
        unsigned elapsed = (start && now != (time_t)-1) ? (unsigned)(now - start) : 0;

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
    }

    free(buf);
    printf("kload: done acc=0x%08x\n", (unsigned)acc);
    return 0;
}

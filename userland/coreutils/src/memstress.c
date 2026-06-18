#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE       4096U
#define CHUNK_KB        16U
#define MAX_CHUNKS      256U
#define DEFAULT_KB      512U
#define DEFAULT_SECONDS 10U
#define MAX_TARGET_KB   (CHUNK_KB * MAX_CHUNKS)

#ifdef ARM_OS_NEWLIB
static struct sysinfo_response memstress_sysinfo;
#endif

static void touch_pages(unsigned char *ptr, unsigned size, unsigned seed)
{
    for (unsigned off = 0; off < size; off += PAGE_SIZE)
        ptr[off] = (unsigned char)(seed + (off >> 12));
    ptr[size - 1] = (unsigned char)(seed ^ 0x5a);
}

static int check_pages(unsigned char *ptr, unsigned size, unsigned seed)
{
    for (unsigned off = 0; off < size; off += PAGE_SIZE) {
        if (ptr[off] != (unsigned char)(seed + (off >> 12)))
            return 0;
    }
    return ptr[size - 1] == (unsigned char)(seed ^ 0x5a);
}

static void print_malloc_stats(const char *label)
{
#ifdef ARM_OS_NEWLIB
    int n = getsysinfo(&memstress_sysinfo);
    if (n < 0)
        return;

    for (int i = 0; i < n; i++) {
        struct proc_info *p = &memstress_sysinfo.procs[i];
        if (p->pid == getpid()) {
            printf("memstress: %s heap=%uKB rss=%uKB vm=%uKB pf=%u cow=%u\n",
                   label,
                   p->heap_kb,
                   p->rss_kb,
                   p->vm_kb,
                   p->page_faults,
                   p->cow_faults);
            return;
        }
    }
#else
    struct malloc_stats stats;

    if (malloc_get_stats(&stats) < 0)
        return;

    printf("memstress: %s mapped=%uKB used=%uKB free=%uKB blocks=%u free_blocks=%u\n",
           label,
           (unsigned)(stats.heap_mapped / 1024),
           (unsigned)(stats.heap_used / 1024),
           (unsigned)(stats.heap_free / 1024),
           (unsigned)stats.block_count,
           (unsigned)stats.free_count);
#endif
}

static unsigned parse_positive_arg(const char *arg, unsigned fallback)
{
    int value;

    if (!arg)
        return fallback;

    value = atoi(arg);
    if (value <= 0)
        return fallback;

    return (unsigned)value;
}

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s [memory_kb] [hold_seconds]\n", prog);
    printf("  %s --cpu [seconds]\n", prog);
}

static int run_cpu_stress(unsigned seconds)
{
    volatile unsigned acc = 0x12345678U;
    unsigned loops = 0;
    time_t start = time(NULL);

    printf("memstress: pid=%d cpu-bound hold=%us\n", getpid(), seconds);
    printf("memstress: run ps/lps now; TIME and CTX should increase\n");

    if (start == (time_t)-1) {
        for (unsigned sec = 0; sec < seconds; sec++) {
            for (unsigned batch = 0; batch < 1600U; batch++) {
                for (unsigned i = 0; i < 4096U; i++) {
                    acc ^= (acc << 5) + (acc >> 2) + i + batch;
                    acc = (acc << 7) | (acc >> 25);
                }
                loops++;
            }
            if ((sec + 1U) % 5U == 0 || sec + 1U == seconds)
                printf("memstress: cpu progress %us/%us loops=%u acc=0x%08x\n",
                       sec + 1U, seconds, loops, (unsigned)acc);
        }
        printf("memstress: cpu done loops=%u acc=0x%08x\n", loops, (unsigned)acc);
        return 0;
    }

    while ((unsigned)(time(NULL) - start) < seconds) {
        for (unsigned batch = 0; batch < 128U; batch++) {
            for (unsigned i = 0; i < 4096U; i++) {
                acc ^= (acc << 5) + (acc >> 2) + i + batch;
                acc = (acc << 7) | (acc >> 25);
            }
            loops++;
        }
    }

    printf("memstress: cpu done loops=%u acc=0x%08x\n", loops, (unsigned)acc);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned total_kb = DEFAULT_KB;
    unsigned seconds = DEFAULT_SECONDS;
    unsigned requested_kb;
    unsigned chunk_count;
    unsigned chunk_bytes = CHUNK_KB * 1024U;
    unsigned live_kb = 0;
    unsigned char *chunks[MAX_CHUNKS];
    int ok = 1;

    if (argc > 1 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--cpu") == 0) {
        seconds = parse_positive_arg(argc > 2 ? argv[2] : NULL, DEFAULT_SECONDS);
        return run_cpu_stress(seconds);
    }

    if (argc > 1) {
        total_kb = parse_positive_arg(argv[1], DEFAULT_KB);
    }
    if (argc > 2) {
        seconds = parse_positive_arg(argv[2], DEFAULT_SECONDS);
    }

    requested_kb = total_kb;
    chunk_count = (total_kb + CHUNK_KB - 1) / CHUNK_KB;
    if (chunk_count > MAX_CHUNKS) {
        chunk_count = MAX_CHUNKS;
        total_kb = MAX_TARGET_KB;
    } else {
        total_kb = chunk_count * CHUNK_KB;
    }

    for (unsigned i = 0; i < MAX_CHUNKS; i++)
        chunks[i] = NULL;

    if (requested_kb != total_kb) {
        printf("memstress: requested %uKB, rounded/capped to %uKB "
               "(max=%uKB, chunk=%uKB)\n",
               requested_kb, total_kb, MAX_TARGET_KB, CHUNK_KB);
    }

    printf("memstress: pid=%d target=%uKB chunks=%u hold=%us x2 total~%us\n",
           getpid(), total_kb, chunk_count, seconds, seconds * 2U);
    printf("memstress: hold phases sleep; use '--cpu N' to test ps TIME/CTX\n");
    print_malloc_stats("initial");

    for (unsigned i = 0; i < chunk_count; i++) {
        chunks[i] = malloc(chunk_bytes);
        if (!chunks[i]) {
            printf("memstress: malloc failed at chunk %u\n", i);
            ok = 0;
            break;
        }
        touch_pages(chunks[i], chunk_bytes, 0x20U + i);
        live_kb += CHUNK_KB;
    }

    for (unsigned i = 0; i < chunk_count && chunks[i]; i++) {
        if (!check_pages(chunks[i], chunk_bytes, 0x20U + i)) {
            printf("memstress: corruption in chunk %u\n", i);
            ok = 0;
        }
    }

    printf("memstress: allocated and touched %uKB, run ps now\n", live_kb);
    print_malloc_stats("after alloc");
    sleep(seconds);

    for (unsigned i = 1; i < chunk_count; i += 2) {
        if (chunks[i]) {
            free(chunks[i]);
            chunks[i] = NULL;
        }
    }

    printf("memstress: freed alternating chunks, reallocating smaller blocks\n");
    for (unsigned i = 1; i < chunk_count; i += 2) {
        chunks[i] = malloc(chunk_bytes / 2);
        if (!chunks[i]) {
            ok = 0;
            continue;
        }
        touch_pages(chunks[i], chunk_bytes / 2, 0x80U + i);
    }

    printf("memstress: reuse phase ready, run ps again\n");
    print_malloc_stats("after reuse");
    sleep(seconds);

    for (unsigned i = 0; i < chunk_count; i++) {
        if (chunks[i])
            free(chunks[i]);
    }

    print_malloc_stats("after free");
    printf("memstress: done%s\n", ok ? "" : " with errors");
    return ok ? 0 : 1;
}

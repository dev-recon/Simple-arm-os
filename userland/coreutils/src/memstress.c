#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE       4096U
#define CHUNK_KB        16U
#define MAX_CHUNKS      256U
#define DEFAULT_KB      512U
#define DEFAULT_SECONDS 10U

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
}

int main(int argc, char **argv)
{
    unsigned total_kb = DEFAULT_KB;
    unsigned seconds = DEFAULT_SECONDS;
    unsigned chunk_count;
    unsigned chunk_bytes = CHUNK_KB * 1024U;
    unsigned live_kb = 0;
    unsigned char *chunks[MAX_CHUNKS];
    int ok = 1;

    if (argc > 1) {
        int value = atoi(argv[1]);
        if (value > 0)
            total_kb = (unsigned)value;
    }
    if (argc > 2) {
        int value = atoi(argv[2]);
        if (value > 0)
            seconds = (unsigned)value;
    }

    chunk_count = (total_kb + CHUNK_KB - 1) / CHUNK_KB;
    if (chunk_count > MAX_CHUNKS)
        chunk_count = MAX_CHUNKS;

    for (unsigned i = 0; i < MAX_CHUNKS; i++)
        chunks[i] = NULL;

    printf("memstress: pid=%d target=%uKB chunks=%u hold=%us\n",
           getpid(), chunk_count * CHUNK_KB, chunk_count, seconds);
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

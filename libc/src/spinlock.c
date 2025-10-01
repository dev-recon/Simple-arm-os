#include <../include/stdint.h>



/* cpu_relax : hint pour la boucle d'attente */
static inline void cpu_relax(void)
{
    /* wfe is fine if supported; fallback to nop */
    asm volatile("wfe" ::: "memory");
}

/* Try to acquire lock once. Returns 1 on success, 0 on failure. */
static inline int try_lock(volatile uint32_t *lock)
{
    uint32_t old, res;
    asm volatile(
        "ldrex   %0, [%2]\n"        /* old = *lock */
        "cmp     %0, #0\n"
        "strexeq %1, %3, [%2]\n"   /* if old==0 then try *lock = 1 ; res = strex result (0=success) */
        : "=&r" (old), "=&r" (res)
        : "r" (lock), "r" (1)
        : "cc", "memory");
    /* Success if old was 0 and strex returned 0 (res == 0). If old != 0, res contains old. */
    return (old == 0 && res == 0) ? 1 : 0;
}

/* Acquire lock (spin) */
static inline void spin_lock(volatile uint32_t *lock)
{
    /* Fast path: try once, otherwise spin */
    while (!try_lock(lock)) {
        /* Busy-wait: spin until lock appears free, then retry atomic LDREX/STREX */
        while (*lock) {
            cpu_relax();
        }
    }
    /* Full barrier after acquiring lock */
    asm volatile("dmb" ::: "memory");
}

/* Release lock */
static inline void spin_unlock(volatile uint32_t *lock)
{
    /* Ensure ordered stores before unlocking */
    asm volatile("dmb" ::: "memory");
    *lock = 0;
    /* Wake up waiting CPUs (if using WFE/SEV) */
    asm volatile("sev" ::: "memory");
}


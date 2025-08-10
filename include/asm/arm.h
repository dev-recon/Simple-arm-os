/* include/asm/arm.h - Version corrigee sans conflits */
#ifndef _ASM_ARM_H
#define _ASM_ARM_H

/* ARM32 specific definitions */
#define ARM_MODE_USR    0x10
#define ARM_MODE_FIQ    0x11
#define ARM_MODE_IRQ    0x12
#define ARM_MODE_SVC    0x13
#define ARM_MODE_ABT    0x17
#define ARM_MODE_UND    0x1B
#define ARM_MODE_SYS    0x1F

/* CPSR flags */
#define ARM_CPSR_I      (1 << 7)    /* IRQ disable */
#define ARM_CPSR_F      (1 << 6)    /* FIQ disable */
#define ARM_CPSR_T      (1 << 5)    /* Thumb state */
#define ARM_CPSR_MODE   0x1F        /* Mode mask */

/* Cortex-A15 specific features */
#define ARM_CORTEX_A15_FEATURES     1
#define ARM_HAS_NEON                1
#define ARM_HAS_VFP                 1
#define ARM_HAS_GENERIC_TIMER       1
#define ARM_HAS_LARGE_PHYS_ADDR     1
#define ARM_HAS_VIRTUALIZATION      1

#ifdef __GNUC__
#define INLINE static __inline__
#else
#define INLINE static
#endif

/* Inline assembly helpers - Compatible GNU89 et optimise pour Cortex-A15 */
INLINE void enable_interrupts(void) 
{
    __asm__ volatile("cpsie i" ::: "memory");
}

INLINE void disable_interrupts(void) 
{
    __asm__ volatile("cpsid i" ::: "memory");
}

INLINE void enable_fiq(void) 
{
    __asm__ volatile("cpsie f" ::: "memory");
}

INLINE void disable_fiq(void) 
{
    __asm__ volatile("cpsid f" ::: "memory");
}

INLINE void wait_for_interrupt(void) 
{
    __asm__ volatile("wfi" ::: "memory");
}

INLINE void wait_for_event(void) 
{
    __asm__ volatile("wfe" ::: "memory");
}

INLINE void send_event(void) 
{
    __asm__ volatile("sev" ::: "memory");
}

/* Memory barriers optimisees pour Cortex-A15 */
INLINE void data_sync_barrier(void) 
{
    __asm__ volatile("dsb sy" ::: "memory");
}

INLINE void data_sync_barrier_read(void) 
{
    __asm__ volatile("dsb ld" ::: "memory");
}

INLINE void data_sync_barrier_write(void) 
{
    __asm__ volatile("dsb st" ::: "memory");
}

INLINE void instruction_sync_barrier(void) 
{
    __asm__ volatile("isb" ::: "memory");
}

INLINE void data_memory_barrier(void) 
{
    __asm__ volatile("dmb sy" ::: "memory");
}

INLINE void data_memory_barrier_read(void) 
{
    __asm__ volatile("dmb ld" ::: "memory");
}

INLINE void data_memory_barrier_write(void) 
{
    __asm__ volatile("dmb st" ::: "memory");
}

/* CPU mode switching helpers */
INLINE uint32_t get_cpsr(void)
{
    uint32_t cpsr;
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    return cpsr;
}

INLINE void set_cpsr(uint32_t cpsr)
{
    __asm__ volatile("msr cpsr_cxsf, %0" : : "r"(cpsr));
}

INLINE uint32_t get_spsr(void)
{
    uint32_t spsr;
    __asm__ volatile("mrs %0, spsr" : "=r"(spsr));
    return spsr;
}

INLINE void set_spsr(uint32_t spsr)
{
    __asm__ volatile("msr spsr_cxsf, %0" : : "r"(spsr));
}

/* CPU identification pour Cortex-A15 */
INLINE uint32_t get_cpu_id(void)
{
    uint32_t cpu_id;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 5" : "=r"(cpu_id));
    return cpu_id & 0x3;  /* CPU ID dans les bits 1:0 */
}

INLINE uint32_t get_main_id(void)
{
    uint32_t main_id;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(main_id));
    return main_id;
}

/* Cache operations pour Cortex-A15 */
INLINE void flush_icache(void)
{
    __asm__ volatile("mcr p15, 0, %0, c7, c5, 0" : : "r"(0));
    instruction_sync_barrier();
}

INLINE void flush_dcache(void)
{
    __asm__ volatile("mcr p15, 0, %0, c7, c6, 0" : : "r"(0));
    data_sync_barrier();
}

INLINE void flush_cache_all(void)
{
    __asm__ volatile("mcr p15, 0, %0, c7, c7, 0" : : "r"(0));
    data_sync_barrier();
    instruction_sync_barrier();
}

INLINE void clean_dcache_range(uint32_t start, uint32_t end)
{
    uint32_t addr;
    for (addr = start & ~63; addr < end; addr += 64) {
        __asm__ volatile("mcr p15, 0, %0, c7, c10, 1" : : "r"(addr));
    }
    data_sync_barrier();
}

INLINE void invalidate_dcache_range(uint32_t start, uint32_t end)
{
    uint32_t addr;
    for (addr = start & ~63; addr < end; addr += 64) {
        __asm__ volatile("mcr p15, 0, %0, c7, c6, 1" : : "r"(addr));
    }
    data_sync_barrier();
}

/* TLB operations */
INLINE void flush_tlb(void)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0));
    data_sync_barrier();
    instruction_sync_barrier();
}

INLINE void flush_tlb_page(uint32_t addr)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 1" : : "r"(addr));
    data_sync_barrier();
    instruction_sync_barrier();
}

/* Branch predictor operations */
INLINE void flush_branch_predictor(void)
{
    __asm__ volatile("mcr p15, 0, %0, c7, c5, 6" : : "r"(0));
    instruction_sync_barrier();
}

/* MMU control */
INLINE uint32_t get_sctlr(void)
{
    uint32_t sctlr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    return sctlr;
}

INLINE void set_sctlr(uint32_t sctlr)
{
    __asm__ volatile("mcr p15, 0, %0, c1, c0, 0" : : "r"(sctlr));
    instruction_sync_barrier();
}

/* 
 * NOTE: get_ttbr0, set_ttbr0, invalidate_tlb_all, invalidate_tlb_page
 * sont declarees dans memory.h et implementees dans mmu.c
 * pour eviter les conflits entre inline et non-inline
 */

INLINE uint32_t get_ttbr1(void)
{
    uint32_t ttbr1;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    return ttbr1;
}

INLINE void set_ttbr1(uint32_t ttbr1)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" : : "r"(ttbr1));
    instruction_sync_barrier();
}

INLINE uint32_t get_ttbcr(void)
{
    uint32_t ttbcr;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    return ttbcr;
}

INLINE void set_ttbcr(uint32_t ttbcr)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 2" : : "r"(ttbcr));
    instruction_sync_barrier();
}

INLINE uint32_t get_dacr(void)
{
    uint32_t dacr;
    __asm__ volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(dacr));
    return dacr;
}

INLINE void set_dacr(uint32_t dacr)
{
    __asm__ volatile("mcr p15, 0, %0, c3, c0, 0" : : "r"(dacr));
    instruction_sync_barrier();
}

/* Fault registers */
INLINE uint32_t get_dfar(void)
{
    uint32_t dfar;
    __asm__ volatile("mrc p15, 0, %0, c6, c0, 0" : "=r"(dfar));
    return dfar;
}

INLINE uint32_t get_ifar(void)
{
    uint32_t ifar;
    __asm__ volatile("mrc p15, 0, %0, c6, c0, 2" : "=r"(ifar));
    return ifar;
}

INLINE uint32_t get_dfsr(void)
{
    uint32_t dfsr;
    __asm__ volatile("mrc p15, 0, %0, c5, c0, 0" : "=r"(dfsr));
    return dfsr;
}

INLINE uint32_t get_ifsr(void)
{
    uint32_t ifsr;
    __asm__ volatile("mrc p15, 0, %0, c5, c0, 1" : "=r"(ifsr));
    return ifsr;
}

/* ARM Generic Timer support pour Cortex-A15 */
INLINE uint32_t get_cntfrq(void)
{
    uint32_t freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(freq));
    return freq;
}

INLINE void set_cntfrq(uint32_t freq)
{
    __asm__ volatile("mcr p15, 0, %0, c14, c0, 0" : : "r"(freq));
}

INLINE uint64_t get_cntpct(void)
{
    uint32_t low, high;
    __asm__ volatile("mrrc p15, 0, %0, %1, c14" : "=r"(low), "=r"(high));
    return ((uint64_t)high << 32) | low;
}

INLINE uint32_t get_cntp_ctl(void)
{
    uint32_t ctl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(ctl));
    return ctl;
}

INLINE void set_cntp_ctl(uint32_t ctl)
{
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" : : "r"(ctl));
}

INLINE uint32_t get_cntp_tval(void)
{
    uint32_t tval;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 0" : "=r"(tval));
    return tval;
}

INLINE void set_cntp_tval(uint32_t tval)
{
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" : : "r"(tval));
}

INLINE uint64_t get_cntp_cval(void)
{
    uint32_t low, high;
    __asm__ volatile("mrrc p15, 2, %0, %1, c14" : "=r"(low), "=r"(high));
    return ((uint64_t)high << 32) | low;
}

INLINE void set_cntp_cval(uint64_t cval)
{
    uint32_t low = (uint32_t)cval;
    uint32_t high = (uint32_t)(cval >> 32);
    __asm__ volatile("mcrr p15, 2, %0, %1, c14" : : "r"(low), "r"(high));
}

/* Performance monitoring pour Cortex-A15 */
INLINE uint32_t get_pmcr(void)
{
    uint32_t pmcr;
    __asm__ volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(pmcr));
    return pmcr;
}

INLINE void set_pmcr(uint32_t pmcr)
{
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(pmcr));
}

INLINE uint32_t get_pmccntr(void)
{
    uint32_t pmccntr;
    __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
    return pmccntr;
}

INLINE void set_pmccntr(uint32_t pmccntr)
{
    __asm__ volatile("mcr p15, 0, %0, c9, c13, 0" : : "r"(pmccntr));
}

/* VFP/NEON support pour Cortex-A15 */
INLINE uint32_t get_cpacr(void)
{
    uint32_t cpacr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 2" : "=r"(cpacr));
    return cpacr;
}

INLINE void set_cpacr(uint32_t cpacr)
{
    __asm__ volatile("mcr p15, 0, %0, c1, c0, 2" : : "r"(cpacr));
    instruction_sync_barrier();
}

INLINE void enable_vfp(void)
{
    uint32_t cpacr = get_cpacr();
    cpacr |= (0xF << 20);  /* Enable CP10 and CP11 */
    set_cpacr(cpacr);
}

INLINE void disable_vfp(void)
{
    uint32_t cpacr = get_cpacr();
    cpacr &= ~(0xF << 20);  /* Disable CP10 and CP11 */
    set_cpacr(cpacr);
}

/* Auxiliary Control Register pour Cortex-A15 */
INLINE uint32_t get_actlr(void)
{
    uint32_t actlr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 1" : "=r"(actlr));
    return actlr;
}

INLINE void set_actlr(uint32_t actlr)
{
    __asm__ volatile("mcr p15, 0, %0, c1, c0, 1" : : "r"(actlr));
    instruction_sync_barrier();
}

/* Cache size identification pour Cortex-A15 */
INLINE uint32_t get_ccsidr(void)
{
    uint32_t ccsidr;
    __asm__ volatile("mrc p15, 1, %0, c0, c0, 0" : "=r"(ccsidr));
    return ccsidr;
}

INLINE uint32_t get_csselr(void)
{
    uint32_t csselr;
    __asm__ volatile("mrc p15, 2, %0, c0, c0, 0" : "=r"(csselr));
    return csselr;
}

INLINE void set_csselr(uint32_t csselr)
{
    __asm__ volatile("mcr p15, 2, %0, c0, c0, 0" : : "r"(csselr));
    instruction_sync_barrier();
}

/* Context ID register */
INLINE uint32_t get_contextidr(void)
{
    uint32_t contextidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    return contextidr;
}

INLINE void set_contextidr(uint32_t contextidr)
{
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 1" : : "r"(contextidr));
    instruction_sync_barrier();
}

/* Thread ID registers */
INLINE uint32_t get_tpidrurw(void)
{
    uint32_t tpidrurw;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 2" : "=r"(tpidrurw));
    return tpidrurw;
}

INLINE void set_tpidrurw(uint32_t tpidrurw)
{
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 2" : : "r"(tpidrurw));
}

INLINE uint32_t get_tpidruro(void)
{
    uint32_t tpidruro;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 3" : "=r"(tpidruro));
    return tpidruro;
}

INLINE void set_tpidruro(uint32_t tpidruro)
{
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 3" : : "r"(tpidruro));
}

INLINE uint32_t get_tpidrprw(void)
{
    uint32_t tpidrprw;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 4" : "=r"(tpidrprw));
    return tpidrprw;
}

INLINE void set_tpidrprw(uint32_t tpidrprw)
{
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 4" : : "r"(tpidrprw));
}

/* Helper functions pour les operations courantes */
INLINE void enable_mmu(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr |= (1 << 0);  /* M bit */
    set_sctlr(sctlr);
}

INLINE void disable_mmu(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr &= ~(1 << 0);  /* M bit */
    set_sctlr(sctlr);
}

INLINE void enable_dcache(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr |= (1 << 2);  /* C bit */
    set_sctlr(sctlr);
}

INLINE void disable_dcache(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr &= ~(1 << 2);  /* C bit */
    set_sctlr(sctlr);
}

INLINE void enable_icache(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr |= (1 << 12);  /* I bit */
    set_sctlr(sctlr);
}

INLINE void disable_icache(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr &= ~(1 << 12);  /* I bit */
    set_sctlr(sctlr);
}

INLINE void enable_branch_prediction(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr |= (1 << 11);  /* Z bit */
    set_sctlr(sctlr);
}

INLINE void disable_branch_prediction(void)
{
    uint32_t sctlr = get_sctlr();
    sctlr &= ~(1 << 11);  /* Z bit */
    set_sctlr(sctlr);
}

/* Macros pour les constantes courantes */
#define SCTLR_M     (1 << 0)    /* MMU enable */
#define SCTLR_A     (1 << 1)    /* Alignment check enable */
#define SCTLR_C     (1 << 2)    /* Data cache enable */
#define SCTLR_W     (1 << 3)    /* Write buffer enable */
#define SCTLR_P     (1 << 4)    /* 32-bit exception handler */
#define SCTLR_D     (1 << 5)    /* 26-bit address exception checking */
#define SCTLR_L     (1 << 6)    /* Late abort on earlier CPUs */
#define SCTLR_B     (1 << 7)    /* Big-endian */
#define SCTLR_S     (1 << 8)    /* System MMU protection */
#define SCTLR_R     (1 << 9)    /* ROM MMU protection */
#define SCTLR_F     (1 << 10)   /* Implementation defined */
#define SCTLR_Z     (1 << 11)   /* Branch prediction enable */
#define SCTLR_I     (1 << 12)   /* Instruction cache enable */
#define SCTLR_V     (1 << 13)   /* Vectors bit */
#define SCTLR_RR    (1 << 14)   /* Round robin replacement */
#define SCTLR_L4    (1 << 15)   /* LDR pc can set T bit */
#define SCTLR_DT    (1 << 16)   /* Global data TCM enable */
#define SCTLR_IT    (1 << 18)   /* Global instruction TCM enable */
#define SCTLR_ST    (1 << 19)   /* Global system TCM enable */
#define SCTLR_FI    (1 << 21)   /* Fast interrupts configuration enable */
#define SCTLR_U     (1 << 22)   /* Unaligned access operation */
#define SCTLR_XP    (1 << 23)   /* Extended page tables */
#define SCTLR_VE    (1 << 24)   /* Vectored interrupts */
#define SCTLR_EE    (1 << 25)   /* Exception endianness */
#define SCTLR_L2    (1 << 26)   /* L2 unified cache enable */
#define SCTLR_NMFI  (1 << 27)   /* Non-maskable FIQ (NMFI) support */
#define SCTLR_TRE   (1 << 28)   /* TEX remap enable */
#define SCTLR_AFE   (1 << 29)   /* Access flag enable */
#define SCTLR_TE    (1 << 30)   /* Thumb exception enable */

/* CPACR bits */
#define CPACR_CP10_MASK (3 << 20)
#define CPACR_CP11_MASK (3 << 22)
#define CPACR_CP10_FULL (3 << 20)
#define CPACR_CP11_FULL (3 << 22)

/* ACTLR bits pour Cortex-A15 */
#define ACTLR_SMP   (1 << 6)    /* SMP mode */
#define ACTLR_L1PEN (1 << 2)    /* L1 prefetch enable */
#define ACTLR_L2PEN (1 << 1)    /* L2 prefetch enable */
#define ACTLR_FW    (1 << 0)    /* Cache and TLB maintenance broadcast */

/* Timer control bits */
#define CNTP_CTL_ENABLE  (1 << 0)
#define CNTP_CTL_IMASK   (1 << 1)
#define CNTP_CTL_ISTATUS (1 << 2)

#endif /* _ASM_ARM_H */
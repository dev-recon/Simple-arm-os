#ifndef _ASM_MMU_H
#define _ASM_MMU_H

#include <kernel/types.h>

/* Bits des entrées de page table (niveau 2) */
#define PTE_TYPE_MASK           0x3
#define PTE_TYPE_FAULT          0x0     /* Page non présente */
#define PTE_TYPE_LARGE          0x1     /* Large page (64KB) */
#define PTE_TYPE_SMALL          0x2     /* Small page (4KB) */
#define PTE_TYPE_TINY           0x3     /* Tiny page (1KB) - obsolète */

/* Bits pour les small pages (4KB) */
#define PTE_SMALL_BASE          0xFFFFF000u
#define PTE_AP_MASK             0xF0    /* Access Permission bits [7:4] */
#define PTE_AP_RW_NA            0x10    /* Kernel RW, User No Access */
#define PTE_AP_RW_RO            0x20    /* Kernel RW, User Read Only */
#define PTE_AP_RW_RW            0x30    /* Kernel RW, User RW */
#define PTE_CACHEABLE           0x8     /* Bit C */
#define PTE_BUFFERABLE          0x4     /* Bit B */

/* Page table entry flags */
#define PTE_PRESENT    (1 << 0)
#define PTE_SMALL      (1 << 1)
#define PTE_CACHE      (1 << 3)
#define PTE_BUFFER     (1 << 2)
#define PTE_ACCESS     (3 << 4)
#define PTE_COW        (1 << 9)

/* Page directory entry flags */
#define PDE_PRESENT    0x00000001
#define PDE_SECTION    (1 << 1)
#define PDE_TABLE      (1 << 0)
#define PDE_CACHE      (1 << 3)
#define PDE_BUFFER     (1 << 2)
#define PDE_ACCESS     (3 << 10)

/* Split TTBR configuration pour Cortex-A15 */
#define TTBCR_N_1GB     0       /* N=0: split à 1GB (0-1GB=TTBR0, 1-4GB=TTBR1) */
#define TTBCR_N_2GB     1       /* N=1: split à 2GB (0-2GB=TTBR0, 2-4GB=TTBR1) */
#define TTBCR_N_3GB     2       /* N=2: split à 3GB (0-3GB=TTBR0, 3-4GB=TTBR1) */

/* Split boundaries */
#define TTBR0_MAX_ADDR_1GB      0x40000000UL    /* 1GB */
#define TTBR0_MAX_ADDR          0x40000000UL    /* 2GB */
#define TTBR0_MAX_ADDR_3GB      0xC0000000UL    /* 3GB */

/* ASID configuration */
#define ASID_BITS               8
#define MAX_ASID                ((1 << ASID_BITS) - 1)
#define ASID_MASK               MAX_ASID
#define CONTEXTIDR_ASID_MASK    ASID_MASK

/* Alternative : juste après la RAM kernel */
#define TEMP_MAPPING_START  0x80000000      /* Juste après la RAM kernel */
#define TEMP_MAPPING_END    0x81000000      /* 16MB pour mappings temporaires */
#define TEMP_MAP_VADDR      TEMP_MAPPING_START
#define TEMP_MAP_SIZE       PAGE_SIZE       /* 4KB page size */

/* Définitions pour les entrées de table de pages ARM Cortex-A15 */
#define PAGE_PRESENT        (1 << 0)    /* Valid bit */
#define PAGE_TABLE          (1 << 1)    /* Page table entry (vs section) */
#define PAGE_BUFFERABLE     (1 << 2)    /* B bit */
#define PAGE_CACHEABLE      (1 << 3)    /* C bit */

/* Access Permission bits [AP] - bits 15, 11:10 */
#define PAGE_AP_NO_ACCESS   (0 << 10)   /* No access */
#define PAGE_AP_SYS_RW      (1 << 10)   /* System R/W, User no access */
#define PAGE_AP_USER_RO     (2 << 10)   /* System R/W, User RO */
#define PAGE_AP_USER_RW     (3 << 10)   /* System R/W, User R/W */

/* Execute Never bit */
#define PAGE_XN             (1 << 0)    /* Execute Never (pour les Small Pages) */
#define PAGE_PXN            (1 << 2)    /* Privileged Execute Never */

/* Combinaisons utiles pour split TTBR */
#define PAGE_USER_CODE      (PAGE_PRESENT | PAGE_AP_USER_RO | PAGE_CACHEABLE)
#define PAGE_USER_DATA      (PAGE_PRESENT | PAGE_AP_USER_RW | PAGE_CACHEABLE | PAGE_XN)
#define PAGE_KERNEL_CODE    (PAGE_PRESENT | PAGE_AP_SYS_RW | PAGE_CACHEABLE)
#define PAGE_KERNEL_DATA    (PAGE_PRESENT | PAGE_AP_SYS_RW | PAGE_CACHEABLE | PAGE_XN)

/* Split TTBR helper macros - éviter les conflits avec kernel.h */
#ifndef IS_USER_ADDR
//#define IS_USER_ADDR(addr)      ((addr) < TTBR0_MAX_ADDR_2GB)
#define IS_USER_ADDR(addr)      ((addr) < SPLIT_BOUNDARY)
#endif
#ifndef IS_KERNEL_ADDR  
//#define IS_KERNEL_ADDR(addr)    ((addr) >= TTBR0_MAX_ADDR_2GB)
#define IS_KERNEL_ADDR(addr)    ((addr) >= SPLIT_BOUNDARY)
#endif
// Pour TTBCR=2, la frontière est à 0x40000000
#define TTBR_SPLIT_BOUNDARY  0x40000000

// Pour les adresses user (0x00000000 - 0x3FFFFFFF) → TTBR0
#define USER_L1_INDEX(addr)     ((addr) >> 20)  // Indices 0-1023

// Pour les adresses kernel (0x40000000 - 0xFFFFFFFF) → TTBR1
// TTBR1 pointe sur kernel_page_dir[1024], donc on doit ajouter 1024
#define KERNEL_L1_INDEX(addr)   (1024 + (((addr) - TTBR_SPLIT_BOUNDARY) >> 20))

#define L2_INDEX(addr)          (((addr) >> 12) & 0xFF)
#define OFFSET(addr)            ((addr) & 0xFFF)


/* MMU functions avec support split TTBR et ASID */
void invalidate_tlb_all(void);
void invalidate_tlb_page(uint32_t vaddr);
void invalidate_tlb_page_asid(uint32_t vaddr, uint32_t asid);
void invalidate_tlb_asid(uint32_t asid);

/* TTBR access functions - déclarées ici, implémentées dans mmu.c pour éviter conflits inline */
uint32_t get_ttbr0(void);
void set_ttbr0(uint32_t ttbr0);

/* Page directory size helpers pour split TTBR */
static inline uint32_t get_user_pgdir_size(uint32_t ttbcr_n)
{
    /* TTBR0 size dépend de N */
    switch(ttbcr_n) {
        case TTBCR_N_1GB: return 1024 * 4;  /* 1024 entrées * 4 bytes = 4KB */
        case TTBCR_N_2GB: return 2048 * 4;  /* 2048 entrées * 4 bytes = 8KB */
        case TTBCR_N_3GB: return 3072 * 4;  /* 3072 entrées * 4 bytes = 12KB */
        default: return 4096 * 4;           /* Full 4KB si pas de split */
    }
}

static inline uint32_t get_kernel_pgdir_size(uint32_t ttbcr_n)
{
    /* TTBR1 size dépend de N */
    switch(ttbcr_n) {
        case TTBCR_N_1GB: return 3072 * 4;  /* 3072 entrées * 4 bytes = 12KB */
        case TTBCR_N_2GB: return 2048 * 4;  /* 2048 entrées * 4 bytes = 8KB */
        case TTBCR_N_3GB: return 1024 * 4;  /* 1024 entrées * 4 bytes = 4KB */
        default: return 0;                  /* Pas de TTBR1 si pas de split */
    }
}

/* Address space validation helpers */
static inline bool is_valid_user_addr(uint32_t addr, uint32_t ttbcr_n)
{
    switch(ttbcr_n) {
        case TTBCR_N_1GB: return addr < TTBR0_MAX_ADDR;
        case TTBCR_N_2GB: return addr < TTBR0_MAX_ADDR;
        case TTBCR_N_3GB: return addr < TTBR0_MAX_ADDR;
        default: return true;  /* Pas de limite si pas de split */
    }
}

static inline bool is_valid_kernel_addr(uint32_t addr, uint32_t ttbcr_n)
{
    switch(ttbcr_n) {
        case TTBCR_N_1GB: return addr >= TTBR0_MAX_ADDR;
        case TTBCR_N_2GB: return addr >= TTBR0_MAX_ADDR;
        case TTBCR_N_3GB: return addr >= TTBR0_MAX_ADDR;
        default: return false;  /* Pas de split = pas d'espace kernel séparé */
    }
}

/* TLB operation helpers with ASID */
static inline void tlb_flush_all(void)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0));  /* TLBIALL */
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

static inline void tlb_flush_by_va(uint32_t vaddr)
{
    vaddr &= ~0xFFF;  /* Page align */
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 1" : : "r"(vaddr));  /* TLBIMVA */
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

static inline void tlb_flush_by_asid(uint32_t asid)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 2" : : "r"(asid & ASID_MASK));  /* TLBIASID */
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

static inline void tlb_flush_by_va_asid(uint32_t vaddr, uint32_t asid)
{
    uint32_t tlbimvaa_val = (vaddr & ~0xFFF) | (asid & ASID_MASK);
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 3" : : "r"(tlbimvaa_val));  /* TLBIMVAA */
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

/* TTBCR configuration helpers */
static inline uint32_t ttbcr_build(uint32_t n, bool pd0, bool pd1)
{
    uint32_t ttbcr = n & 0x7;  /* N field */
    if (pd0) ttbcr |= (1 << 4);  /* PD0 - disable table walks for TTBR0 */
    if (pd1) ttbcr |= (1 << 5);  /* PD1 - disable table walks for TTBR1 */
    return ttbcr;
}

static inline uint32_t ttbcr_get_n(uint32_t ttbcr)
{
    return ttbcr & 0x7;
}

static inline bool ttbcr_get_pd0(uint32_t ttbcr)
{
    return (ttbcr & (1 << 4)) != 0;
}

static inline bool ttbcr_get_pd1(uint32_t ttbcr)
{
    return (ttbcr & (1 << 5)) != 0;
}

/* CONTEXTIDR helpers */
static inline uint32_t contextidr_build(uint32_t asid, uint32_t procid)
{
    return (asid & ASID_MASK) | ((procid & 0xFFFFFF) << 8);
}

static inline uint32_t contextidr_get_asid(uint32_t contextidr)
{
    return contextidr & ASID_MASK;
}

static inline uint32_t contextidr_get_procid(uint32_t contextidr)
{
    return (contextidr >> 8) & 0xFFFFFF;
}

/* Memory barrier helpers optimisés pour split TTBR */
static inline void mmu_dsb(void)
{
    __asm__ volatile("dsb" ::: "memory");
}

static inline void mmu_isb(void)
{
    __asm__ volatile("isb" ::: "memory");
}

static inline void mmu_dmb(void)
{
    __asm__ volatile("dmb" ::: "memory");
}

/* Page directory entry helpers pour split TTBR */
static inline bool pde_is_section(uint32_t pde)
{
    return (pde & 0x3) == 0x2;
}

static inline bool pde_is_page_table(uint32_t pde)
{
    return (pde & 0x3) == 0x1;
}

static inline bool pde_is_fault(uint32_t pde)
{
    return (pde & 0x3) == 0x0;
}

static inline uint32_t pde_get_section_addr(uint32_t pde)
{
    return pde & 0xFFF00000;  /* Bits 31:20 */
}

static inline uint32_t pde_get_page_table_addr(uint32_t pde)
{
    return pde & 0xFFFFFC00;  /* Bits 31:10 */
}

/* Page table entry helpers */
static inline bool pte_is_small_page(uint32_t pte)
{
    return (pte & 0x3) == 0x2;
}

static inline bool pte_is_large_page(uint32_t pte)
{
    return (pte & 0x3) == 0x1;
}

static inline bool pte_is_fault(uint32_t pte)
{
    return (pte & 0x3) == 0x0;
}

static inline uint32_t pte_get_small_page_addr(uint32_t pte)
{
    return pte & 0xFFFFF000;  /* Bits 31:12 */
}

static inline uint32_t pte_get_large_page_addr(uint32_t pte)
{
    return pte & 0xFFFF0000;  /* Bits 31:16 */
}

/* Split TTBR debug helpers */
static inline const char* get_ttbcr_n_name(uint32_t n)
{
    switch(n) {
        case TTBCR_N_1GB: return "1GB";
        case TTBCR_N_2GB: return "2GB";
        case TTBCR_N_3GB: return "3GB";
        default: return "UNKNOWN";
    }
}


/* Performance counters pour monitoring MMU */
static inline void enable_cycle_counter(void)
{
    uint32_t pmcr;
    __asm__ volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(pmcr));
    pmcr |= 0x1;  /* Enable all counters */
    pmcr |= 0x4;  /* Reset cycle counter */
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(pmcr));
    
    /* Enable cycle counter */
    uint32_t pmcntenset = 0x80000000;  /* Bit 31 = cycle counter */
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 1" : : "r"(pmcntenset));
}

static inline uint32_t read_cycle_counter(void)
{
    uint32_t pmccntr;
    __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
    return pmccntr;
}

uint32_t get_split_boundary(void);
uint32_t get_optimal_ttbcr_n(void);

#define SPLIT_BOUNDARY      get_split_boundary()
#define TTBCR_N_OPTIMAL     get_optimal_ttbcr_n()

#endif /* _ASM_MMU_H */
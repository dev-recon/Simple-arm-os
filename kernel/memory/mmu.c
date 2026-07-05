/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/memory/mmu.c
 * Layer: Kernel / memory management
 *
 * Responsibilities:
 * - Manage physical pages, virtual address spaces, MMU mappings, and ASIDs.
 * - Support user mappings, page faults, and copy-on-write.
 *
 * Notes:
 * - TLB, ASID, and TTBR changes are global stability concerns.
 */

#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>
#include <kernel/debug_print.h>
#include <kernel/display.h>
#include <kernel/task.h>
#include <kernel/tlb.h>
#include <asm/mmu.h>
#include <asm/arm.h>

/* Definitions locales des constantes MMU */
#define MMU_PDE_PRESENT    0x00000001
#define MMU_PDE_SECTION    0x00000002
#define MMU_PDE_CACHE      0x00000008
#define MMU_PDE_BUFFER     0x00000004

/* Configuration TTBR split pour Cortex-A15 */
#define TTBCR_N_SPLIT_2GB   1  /* N=1: split à 2GB (0-2GB=TTBR0, 2-4GB=TTBR1) */
#define TTBCR_PD0           (1 << 4)  /* Disable table walk for TTBR0 on TLB miss */
#define TTBCR_PD1           (1 << 5)  /* Disable table walk for TTBR1 on TLB miss */

/* Gestion ASID */
#define ASID_BITS           8
#define MAX_ASID            ((1 << ASID_BITS) - 1)
#define ASID_MASK           MAX_ASID
#define CONTEXTIDR_ASID_MASK ASID_MASK

/* Page directories séparés avec adresses fixes alignées 16KB */
static l1_entry_t kernel_page_dir[4096] __attribute__((section(".data"), aligned(16384)));  /* TTBR1 */
static l1_entry_t kernel_ttbr0[4096] __attribute__((section(".data"), aligned(16384)));  /* TTBR1 */; /* TTBR0 */

/* Pointeurs globaux */
pgdir_cpu_t kernel_pgdir = kernel_page_dir;   /* TTBR1 - Espace noyau */
pgdir_cpu_t ttbr0_pgdir = kernel_ttbr0;   /* TTBR0 - Espace noyau */

/* Gestion ASID */
static uint32_t current_asid = ASID_KERNEL;
static uint32_t asid_generation = 1;
bool asid_map[MAX_ASID + 1] = {true}; /* ASID 0 réservé */
static uint32_t asid_slot_generation[MAX_ASID + 1];

extern void vectors(void);

/* Nouvelles fonctions pour la gestion ASID */
static uint32_t allocate_asid(void);
static void free_asid(uint32_t asid);
void set_current_asid(uint32_t asid);
uint32_t get_current_asid(void);
static void setup_ttbr_split(void);
static void setup_kernel_space(void);
static void setup_user_template(void);
static void map_kernel_mmio_alias(vaddr_t vaddr, paddr_t paddr);
static bool is_valid_vaddr(vaddr_t vaddr);
paddr_t allocate_l2_page(bool is_kernel);
void check_address_content(paddr_t phys_addr, const char* step);
static int map_user_page_with_perm(pgdir_t pgdir, vaddr_t vaddr,
                                   paddr_t phys_addr, uint32_t vma_flags,
                                   uint32_t asid, bool writable);

static inline uint32_t asid_hw(uint32_t asid)
{
    return asid & ASID_MASK;
}

static inline uint32_t asid_gen(uint32_t asid)
{
    return asid >> ASID_BITS;
}

static inline uint32_t asid_make(uint32_t generation, uint32_t hw_asid)
{
    return (generation << ASID_BITS) | (hw_asid & ASID_MASK);
}

static inline bool asid_hw_reserved(uint32_t hw_asid)
{
    return hw_asid == 0 || hw_asid == ASID_KERNEL;
}

static inline pgdir_cpu_t pgdir_cpu_view(pgdir_t pgdir)
{
    vaddr_t addr = (vaddr_t)pgdir;

    if (virt_in_direct_map(addr))
        return (pgdir_cpu_t)pgdir;
    if (phys_in_direct_map((paddr_t)addr))
        return (pgdir_cpu_t)phys_to_virt((paddr_t)addr);

    return (pgdir_cpu_t)pgdir;
}

static void asid_reserve_special(void)
{
    asid_map[0] = true;
    asid_map[ASID_KERNEL] = true;
    asid_slot_generation[0] = asid_generation;
    asid_slot_generation[ASID_KERNEL] = asid_generation;
}

static bool asid_cookie_valid(uint32_t asid)
{
    uint32_t hw_asid = asid_hw(asid);
    uint32_t generation = asid_gen(asid);

    if (asid_hw_reserved(hw_asid))
        return false;

    return asid_map[hw_asid] && asid_slot_generation[hw_asid] == generation;
}

static void flush_all_tlb_local(void)
{
    data_sync_barrier();
    tlb_flush_all();
}

static uint32_t user_page_flags(uint32_t vma_flags, bool writable)
{
    uint32_t page_flags = 0x02 | 0x0C;  /* small page + B/C */

    page_flags |= writable ? PTE_AP_RW_RW : PTE_AP_RW_RO;
    if (!(vma_flags & VMA_EXEC)) {
        page_flags |= 0x01;             /* XN with small-page 0b11 format */
    }

    return page_flags;
}

static inline void clean_pte_for_mmu(const void *pte)
{
    dc_clean_mva((void *)pte);
    data_sync_barrier_inner_shareable_write();
}

pte_ptr_t get_user_pte(pgdir_t pgdir, vaddr_t vaddr)
{
    if (!pgdir || !is_valid_vaddr(vaddr) || vaddr >= 0x40000000 ||
        (vaddr & (PAGE_SIZE - 1))) {
        return NULL;
    }

    uint32_t l1_index = get_L1_index(vaddr);
    uint32_t l2_index = L2_INDEX(vaddr);
    pgdir_cpu_t pgdir_v = pgdir_cpu_view(pgdir);
    l1_entry_t l1_entry = pgdir_v[l1_index];

    if ((l1_entry & 0x3) != 0x1) {
        return NULL;
    }

    l2_table_t l2_table = (l2_table_t)phys_to_virt((paddr_t)(l1_entry & 0xFFFFFC00));
    return &l2_table[l2_index];
}

static int update_user_pte(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr,
                           uint32_t vma_flags, uint32_t asid, bool writable)
{
    pte_ptr_t pte = get_user_pte(pgdir, vaddr);
    if (!pte || ((*pte & PTE_TYPE_MASK) == PTE_TYPE_FAULT)) {
        return -ENOENT;
    }

    *pte = (phys_addr & PTE_SMALL_BASE) | user_page_flags(vma_flags, writable);
    clean_pte_for_mmu(pte);
    tlb_shootdown_page_asid(vaddr, asid);
    if (vma_flags & VMA_EXEC) {
        sync_icache_for_exec();
    }

    return 0;
}



void setup_kernel_asid_context(void)
{    
    KDEBUG("Setting up ASID %d kernel context...\n", ASID_KERNEL);
    
    /*
     * IMPORTANT : Avec QEMU virt, toute la RAM physique est >= 0x40000000
     * Il n'y a PAS de RAM physique < 0x40000000
     * 
     * Pour TTBR0, nous devons :
     * 1. Allouer une page physique dans la RAM réelle (>= 0x40000000)
     * 2. L'utiliser comme table de pages pour l'espace virtuel TTBR0 (< 0x40000000)
     */
    
    /* Allouer une page physique réelle pour la table TTBR0 */
    //void* ttbr0_phys_page = allocate_pages(2);  // Retourne adresse physique >= 0x40000000
    //if (!ttbr0_phys_page) {
    //    panic("Cannot allocate physical page for TTBR0 table");
   // }
    
    /* Vérifier l'alignement 4KB requis pour les tables de pages ARM */
    //if (ttbr0_phys_addr & 0xFFF) {
         /* Forcer l'alignement si nécessaire */
        //KDEBUG("  Forced alignment: 0x%08X -> 0x%08X\n", ttbr0_phys_addr, aligned_addr);
        
        /* Vérifier que l'adresse alignée est dans la zone allouée */
        //if (aligned_addr >= ttbr0_phys_addr && aligned_addr < ttbr0_phys_addr + (2 * PAGE_SIZE)) {
        //    ttbr0_phys_addr = aligned_addr;
        //    KINFO("create_vm_space: Using aligned address 0x%08X\n", aligned_addr);
        //}
        //else{
        //    panic("Cannot align 4KB physical page for TTBR0 table");
       // }
    //}
    
    /* 
     * Stocker l'adresse physique pour configurer le registre TTBR0
     * Le processeur utilisera cette adresse physique directement
     */
    //kernel_ttbr0 = (uint32_t*)ttbr0_phys_addr;  // Adresse physique de la table
    //ttbr0_pgdir = kernel_ttbr0;
    
    KDEBUG("kernel_ttbr0 (physical) set to: 0x%08X\n", (uint32_t)kernel_ttbr0);
    
    /*
     * Pour initialiser la table, nous devons y accéder via un mapping temporaire
     * car nous sommes en mode kernel (TTBR1) et la table est en RAM physique
     */
    //uint32_t ttbr0_virt = map_temp_page(ttbr0_phys_addr);
    uint32_t* ttbr0_table = ttbr0_pgdir;
    
    KDEBUG("TTBR0 table temporarily mapped at virtual: 0x%08X\n", (uint32_t)ttbr0_table);
    
    /* Initialiser la table (16KB = 4096 entrées de 32-bit) */
    //memset(ttbr0_table, 0, 16 * 1024);  // Vider toute la table

#if(0)
    /*
     * Mapper quelques sections critiques dans l'espace TTBR0 (< 0x40000000)
     * Ces mappings pointent vers la RAM physique (>= 0x40000000)
     */
    int mapped_sections = 0;
    
    /* Exemple : mapper 16MB d'espace user (0x01000000-0x01FFFFFF) 
     * vers de la RAM physique libre */
    void* user_ram = allocate_pages(16);  // 16 pages = 64KB pour commencer
    if (user_ram) {
        uint32_t user_phys_base = (uint32_t)user_ram;
        
        /* Mapper section 0x01000000 vers la RAM user allouée */
        uint32_t virt_section = 0x01000000;  // 16MB dans l'espace TTBR0
        uint32_t phys_section = user_phys_base & 0xFFF00000;  // Aligner sur 1MB
        uint32_t section_index = virt_section >> 20;  // Index dans la table
        
        /* Créer l'entrée de section : physique | permissions */
        ttbr0_table[section_index] = phys_section | 
                                    0x00000002 |  // Section entry
                                    0x00000C00 |  // AP[2:1] = 11 (full access)
                                    0x00000010 |  // User accessible
                                    0x00001000;   // Cacheable
        
        mapped_sections++;
        KDEBUG("User RAM at 0x%08X\n", user_ram);
        KDEBUG("Mapped TTBR0 section 0x%08X -> 0x%08X\n", virt_section, phys_section);
    }
    
    /* Mapper les périphériques critiques (UART par exemple) pour debug userspace */
    uint32_t uart_virt = 0x09000000;  // Même adresse virtuelle que physique
    uint32_t uart_phys = 0x09000000;  // UART physique
    uint32_t uart_index = uart_virt >> 20;
    
    ttbr0_table[uart_index] = uart_phys | 
                             0x00000002 |  // Section entry
                             0x00000C00 |  // AP[2:1] = 11
                             0x00000010 |  // User accessible  
                             0x00000004;   // Device memory (non-cacheable)
    
    mapped_sections++;
    KDEBUG("Mapped UART for userspace: 0x%08X -> 0x%08X\n", uart_virt, uart_phys);
#endif
    /* Libérer le mapping temporaire */
    //unmap_temp_page((void*)ttbr0_virt);
    
    KDEBUG("Kernel ASID %d context configured:\n", ASID_KERNEL);
    KDEBUG("  TTBR0 physical table: 0x%08X\n", (uint32_t)kernel_ttbr0);
    //KDEBUG("  Sections mapped: %d\n", mapped_sections);
    KDEBUG("  Ready to handle userspace virtual addresses < 0x40000000\n");
}

void dump_l1(vaddr_t va) {
    //uint32_t N = 2; // tu l'as déjà
    //uint32_t split = get_split_boundary();
    uint32_t idx = get_L1_index(va);
    uint32_t entry = kernel_page_dir[idx];
    kprintf("[%s] VA=0x%08X idx=%u entry=0x%08X nG=%u AP=%u S=%u TEXCB=%u\n",
        "TAG", va, idx, entry,
        (entry >> 17) & 1,
        (entry >> 10) & 3,
        (entry >> 16) & 1,
        ((entry >> 12) & 7) << 2 | ((entry >> 3) & 3));
}

// REMPLACER les constantes fixes par :
uint32_t get_optimal_ttbcr_n(void)
{
    extern uint32_t __start;
    vaddr_t kernel_start = (vaddr_t)(uintptr_t)&__start;
    
    // Déterminer le split optimal basé sur où se trouve le noyau
    if (kernel_start >= 0xC0000000) return 2;  // N=2: split 3GB (noyau à 3GB+)
    if (kernel_start >= 0x80000000) return 1;  // N=1: split 2GB (noyau à 2GB+) 
    if (kernel_start >= 0x40000000) return 2;  // N=0: split 1GB (noyau à 1GB+)
    
    // Si noyau < 1GB, pas de split TTBR (utiliser TTBR0 uniquement)
    return 7;  // Valeur d'erreur
}


vaddr_t get_split_boundary(void)
{
    int n = 2;
    switch(n) {
        case 0: return 0xFFFFFFFF;  // Pas de split
        case 1: return 0x80000000;  // 2GB  
        case 2: return 0x40000000;  // 1GB  ← VOTRE CAS
        case 3: return 0x20000000;  // 512MB
        case 4: return 0x10000000;  // 256MB
        case 5: return 0x08000000;  // 128MB
        case 6: return 0x04000000;  // 64MB
        case 7: return 0x02000000;  // 32MB
        default: return 0x40000000;
    }
}


/* Fonction de detection rapide pour MMU setup (inchangée) */
static uint32_t detect_available_ram_for_mmu(void)
{
    struct {
        uint32_t size_mb;
        uint32_t test_addr;
        const char* name;
    } quick_tests[] = {
        { 1024, VIRT_RAM_START + ((1024U * 1024U * 1024U)) - 0x100000, "1GB" },
        { 2048, VIRT_RAM_START + (2048ULL*1024*1024) - 0x100000, "2GB" },  
    };
    
    for (int i = 1; i >= 0; i--) {
        volatile uint32_t* test_ptr = (volatile uint32_t*)quick_tests[i].test_addr;
        
        uint32_t original = *test_ptr;
        *test_ptr = 0xDEADBEEF;
        
        if (*test_ptr == 0xDEADBEEF) {
            *test_ptr = original;
            KINFO("MMU: Quick test found %s of RAM\n", quick_tests[i].name);
            return quick_tests[i].size_mb * 1024 * 1024;
        }
    }
    
    KINFO("MMU: Quick test failed, using 1GB fallback\n");
    return 1024 * 1024 * 1024;
}

void configure_alignment_policy(void) {
    uint32_t sctlr = get_sctlr();
    
    KINFO("Current SCTLR = 0x%08X\n", sctlr);
    KINFO("Alignment checking: %s\n", (sctlr & (1<<1)) ? "ENABLED" : "DISABLED");
    
    // Desactiver l'alignement strict
    sctlr &= ~(1 << 1);  // Clear A bit
    
    set_sctlr(sctlr);
    data_sync_barrier();
    instruction_sync_barrier();
    
    KINFO("Alignment checking disabled OK\n");
}

void check_endianness() {
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};

    KINFO("Endianness test:\n");
    KINFO("  32-bit integer value: 0x%08X\n", bint.i);
    KINFO("  Byte order:   %02X %02X %02X %02X\n", 
            bint.c[0], bint.c[1], bint.c[2], bint.c[3]);

    if (bint.c[0] == 0x01) {
        KINFO("  System is BIG ENDIAN\n");
    } else if (bint.c[0] == 0x04) {
        KINFO("  System is LITTLE ENDIAN\n");
    } else {
        KINFO("  Unexpected endianness!\n");
    }

    // Vérification spécifique ARM
    uint32_t cpsr;
    cpsr = read_cpsr();
    bool ee_bit = (cpsr & (1 << 9)) != 0;
    KINFO("  CPSR Endian Exception bit: %s\n", 
            ee_bit ? "SET (Big Endian)" : "CLEAR (Little Endian)");
}


bool setup_mmu(void)
{
    check_endianness();

    setup_kernel_asid_context();

    setup_kernel_space();

    //preallocate_temp_mapping_system();  // Pendant qu'on a l'identity mapping
    //create_l2_access_zone();            // Idem

        // 3. Configurer TTBR0 (userspace)
    uint32_t ttbr0_value = (uint32_t)ttbr0_pgdir |
                          TTBR_RGN_OUTER_WBWA |  // Outer write-back write-allocate
                          TTBR_SHAREABLE |       // Shareable
                          TTBR_CACHEABLE;        // Cacheable
    
    // 4. Configurer TTBR1 (kernel)  
    uint32_t ttbr1_value = (uint32_t)kernel_page_dir |
                          TTBR_RGN_OUTER_WBWA |  // Outer write-back write-allocate
                          TTBR_SHAREABLE |       // Shareable
                          TTBR_CACHEABLE;        // Cacheable
    
    // 5. Configurer TTBCR avec IRGN
    uint32_t ttbcr_value = 2 |                    // N=2 (split à 0x40000000)
                          TTBCR_IRGN0_WBWA |     // Inner cacheable TTBR0
                          TTBCR_IRGN1_WBWA;      // Inner cacheable TTBR1

    ttbr0_value = (uint32_t)ttbr0_pgdir;
    ttbr1_value = (uint32_t)kernel_page_dir;
    
    // Écriture des TTBR
    set_ttbr0(ttbr0_value);
    set_ttbr1(ttbr1_value);

    // TTBCR : N = 2 (split à 0x40000000), EAE = 0 (format court)
    uint32_t ttbcr = 0x2; //0x2;
    ttbcr_value = ttbcr;
    set_ttbcr(ttbcr_value);

    data_sync_barrier();
    instruction_sync_barrier();

// Vérifier immédiatement
uint32_t ttbcr_check;
ttbcr_check = get_ttbcr();
KDEBUG("TTBCR written: 0x%08X, read back: 0x%08X\n", ttbcr_value, ttbcr_check);

if (ttbcr_check != ttbcr_value) {
    KERROR("TTBCR write failed!\n");
    KERROR("  Written: 0x%08X\n", ttbcr_value);
    KERROR("  Read:    0x%08X\n", ttbcr_check);
    while(1);
}

    // Synchronisation
    data_sync_barrier();
    instruction_sync_barrier();

    /* === Invalider TLB et caches === */
    tlb_flush_all();
    flush_cache_all();

    /* === DACR (Domain Access Control) === */
    uint32_t dacr = 0x55555555;
    set_dacr(dacr);

    /* === Lire et modifier SCTLR === */
    uint32_t sctlr = 0;

    // Activer les configurations essentielles
    sctlr |= (1 << 0);   // M  : MMU enable
    sctlr |= (1 << 1);   // A  : Strict alignment
    sctlr |= (1 << 2);   // C  : Data cache
    sctlr |= (1 << 11);  // Z  : Branch prediction
    sctlr |= (1 << 12);  // I  : Instruction cache
    //sctlr |= (1 << 22);  // U  : Unaligned access

    debug_print_hex("MMU: Cleaned SCTLR = ", sctlr);

    vaddr_t next_pc = arm_current_pc_plus_16();

    debug_print_hex("MMU: Next PC = ", next_pc);

    uint32_t next_index = get_L1_index(next_pc);

    KDEBUG("MMU: Next Index = %d\n", next_index);
    uint32_t next_entry = kernel_page_dir[next_index];
    KDEBUG("MMU: Next Entry = 0x%08X\n", next_entry);

    if ((next_entry & 0x3) != 0x2) {
        simple_kprintf("CRITICAL: Next PC not mapped as section!\n");
        while (1);
    }

// 2. Vérifier les registres TTBR
uint32_t check_ttbr0, check_ttbr1, check_ttbcr;
check_ttbr0 = get_ttbr0();
check_ttbr1 = get_ttbr1();
check_ttbcr = get_ttbcr();

KDEBUG("TTBR0 reg: 0x%08X (expected: 0x%08X)\n", check_ttbr0, ttbr0_value);
KDEBUG("TTBR1 reg: 0x%08X (expected: 0x%08X)\n", check_ttbr1, ttbr1_value);
KDEBUG("TTBCR reg: 0x%08X (expected: 0x%08X)\n", check_ttbcr, ttbcr_value);

// 3. Vérifier l'alignement des tables
if ((uint32_t)ttbr0_pgdir & 0xFFF) {
    KERROR("TTBR0 table not 4KB aligned: 0x%08X\n", (uint32_t)ttbr0_pgdir);
    while(1);
}

if ((uint32_t)kernel_page_dir & 0x3FFF) {
    KERROR("TTBR1 table not 16KB aligned: 0x%08X\n", (uint32_t)kernel_page_dir);
    while(1);
}

// 4. Vérifier quelques entrées critiques
//KDEBUG("TTBR0 entry [0]: 0x%08X\n", ttbr0_pgdir[0]);  // 0x00000000
//KDEBUG("TTBR0 entry [1]: 0x%08X\n", ttbr0_pgdir[1]);  // 0x00100000
//KDEBUG("Kernel entry [0]: 0x%08X\n", kernel_page_dir[0]);  // 0x40000000
//KDEBUG("Kernel entry [1]: 0x%08X\n", kernel_page_dir[1]);  // 0x40100000

KDEBUG("All checks passed, proceeding with MMU activation...\n");

    /* === Activer la MMU === */
    set_sctlr(sctlr);
    data_sync_barrier();
    instruction_sync_barrier();

    KDEBUG("MMU ACTIVATED .....\n");

    KDEBUG("MMU: Post-activation test 1");
    
    /* Verify MMU is enabled */
    uint32_t sctlr_final;
    sctlr_final = get_sctlr();
    debug_print_hex("MMU: Final SCTLR = ", sctlr_final);

    // Reconfigurer VBAR apres MMU ON
    uint32_t vbar_addr = (uint32_t)&vectors;
    set_vbar(vbar_addr);

    // Activer les exceptions
    enable_async_abort_irq_fiq();

    // Desactive l'alignement
    configure_alignment_policy();

    /* Initialiser ASID par défaut pour le noyau */
    set_current_asid(ASID_KERNEL);  /* ASID 0 pour le noyau */

    init_temp_mapping_system();
    
    if (sctlr_final & 0x00000001) {
        simple_kprintf("SUCCESS: MMU with split TTBR and ASID is now active!");
        simple_kprintf("SUCCESS: Virtual memory enabled!");
        return true;
    } else {
        simple_kprintf("ERROR: MMU failed to activate!");
        return false;
    }

}



static void map_kernel_mmio_alias(vaddr_t vaddr, paddr_t paddr)
{
    uint32_t index = get_L1_index(vaddr);

    if ((vaddr & (KERNEL_MMIO_SECTION_SIZE - 1)) ||
        (paddr & (KERNEL_MMIO_SECTION_SIZE - 1)) ||
        vaddr < get_split_boundary()) {
        panic("Invalid kernel MMIO alias");
    }

    if (kernel_page_dir[index] != 0) {
        panic("Kernel MMIO alias overlaps an existing mapping");
    }

    kernel_page_dir[index] = paddr |
                             0x00000002 |  /* Section descriptor */
                             0x00000400 |  /* AP[1:0] = 01: privileged RW */
                             0x00000010 |  /* XN: never execute MMIO */
                             0x00000004 |  /* TEX/C/B = 000/0/1: Device */
                             0x00010000;   /* Shareable */
}


static void setup_kernel_space(void)
{
    vaddr_t split_boundary = get_split_boundary();  // 0x40000000 avec N=2
    uint64_t ram_end = (uint64_t)VIRT_RAM_START + get_kernel_memory_size();
    if (ram_end > 0x100000000ULL) {
        ram_end = 0x100000000ULL;
    }
    uint32_t mapped_sections = 0;
    uint32_t mapped_identity = 0;
    uint32_t mapped_direct = 0;
    uint32_t mapped_low = 0;
    uint32_t mapped_devices = 0;

    
    //kprintf("MMU: Setting up kernel space (TTBR1) from 0x%08X...\n", split_boundary);
    //kprintf("MMU: (TTBR0) from 0x%08X...\n", (uint32_t)ttbr0_pgdir);

    //kprintf("MMU: Mapping range 0x%08X - 0x%08X\n", split_boundary, ram_end);
    //kprintf("MMU: Max index will be %u (limit: 3072)\n", 
    //    ((ram_end-1) >> 20) - (split_boundary >> 20));
    
    /* Clear kernel page directory */
    memset(kernel_page_dir, 0, sizeof(kernel_page_dir));
    memset(ttbr0_pgdir, 0, sizeof(ttbr0_pgdir));


    // 1. Mapper TOUTE la zone basse (0-1GB) en identity mapping dans TTBR0
     for (vaddr_t addr = 0; addr < split_boundary; addr += 0x100000) {
        uint32_t index = get_L1_index(addr);  // Index 0-1023
        //kernel_page_dir[index] = addr | 0xC0E;
        ttbr0_pgdir[index] = addr | 0xC0E;
        mapped_low++;
    }

    KINFO("Mapped low memory (TTBR0): 0x0 - 0x40000000 - %u sections\n", mapped_low);

    /* Map device space */
    for (paddr_t addr = DEVICE_START; addr < DEVICE_END; addr += 0x100000) {

        uint32_t index = get_L1_index(addr);
        
        // Devices: non-cacheable, non-bufferable
        ttbr0_pgdir[index] = addr | 
                0x00000002 |  // Section descriptor
                0x00000C00 |  // AP[2:1] = 11 (full access)
                0x00000004 |  // TEX[0], C, B = 001 (device memory)
                0x00000000 |  // Domain 0
                0x00000000 |  // nG = 0 (global)
                0x00000000;   // S = 0 (non-shared, OK pour device)

        kernel_page_dir[index] = addr | 
                0x00000002 |  // Section descriptor
                0x00000C00 |  // AP[2:1] = 11 (full access)
                0x00000004 |  // TEX[0], C, B = 001 (device memory)
                0x00000000 |  // Domain 0
                0x00000000 |  // nG = 0 (global)
                0x00000000;   // S = 0 (non-shared, OK pour device)

                            //0x00000002 |  // Section entry
                            //0x00000C00 |  // AP[2:1] = 11
                            //0x00000010 |  // User accessible  
                            //0x00000004;   // Device memory (non-cacheable)
        mapped_devices++;
        
    }

    KINFO("Mapped devices sections (TTBR0-TTBR1): 0x0 - 0x40000000 - %u sections\n", mapped_devices);
    
    /*
     * Keep only a small identity window for the current low-linked kernel and
     * early boot metadata.  General RAM is accessed through the direct map
     * below; do not extend this back to all RAM.
     */
    uint64_t identity_end = KERNEL_BOOT_IDENTITY_END;
    if (identity_end > ram_end) {
        identity_end = ram_end;
    }

    for (uint64_t addr64 = split_boundary; addr64 < identity_end; addr64 += 0x100000) {
        vaddr_t addr = (vaddr_t)addr64;
        uint32_t ttbr1_index = get_L1_index(addr);

        kernel_page_dir[ttbr1_index] = addr |
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */

        mapped_identity++;
        mapped_sections++;
    }

    /*
     * Explicit RAM direct map:
     *   KERNEL_DIRECT_MAP_BASE + (paddr - VIRT_RAM_START) -> paddr
     */
    uint64_t direct_phys_end = ram_end;
    uint64_t direct_max_phys = (uint64_t)VIRT_RAM_START + KERNEL_DIRECT_MAP_SIZE;
    if (direct_phys_end > direct_max_phys) {
        direct_phys_end = direct_max_phys;
        KWARN("MMU: direct map truncated RAM above 0x%08X\n", (uint32_t)direct_phys_end);
    }

    for (uint64_t paddr64 = VIRT_RAM_START; paddr64 < direct_phys_end; paddr64 += 0x100000) {
        paddr_t paddr = (paddr_t)paddr64;
        vaddr_t vaddr = phys_to_virt(paddr);
        uint32_t ttbr1_index = get_L1_index(vaddr);

        if (vaddr >= TEMP_MAPPING_START && vaddr < TEMP_MAPPING_END) {
            continue;
        }

        kernel_page_dir[ttbr1_index] = paddr |
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000010 |      /* XN: direct-map RAM is data */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */

        mapped_direct++;
        mapped_sections++;
    }
    
    KINFO("MMU: Boot identity RAM sections mapped: %u (0x%08X-0x%08X)\n",
          mapped_identity, split_boundary, (uint32_t)identity_end);
    KINFO("MMU: Direct-map RAM sections mapped: %u (VA 0x%08X-0x%08X)\n",
          mapped_direct, KERNEL_DIRECT_MAP_BASE, KERNEL_DIRECT_MAP_END);

    /*
     * Alias MMIO prives dans TTBR1. Ils sont additifs pour l'instant:
     * les pilotes continuent d'utiliser les adresses physiques basses.
     */
    map_kernel_mmio_alias(KERNEL_MMIO_GIC_BASE, VIRT_GIC_DIST_BASE);
    map_kernel_mmio_alias(KERNEL_MMIO_UART_BASE, VIRT_UART_BASE);
    map_kernel_mmio_alias(KERNEL_MMIO_VIRTIO_BASE, VIRT_VIRTIO_BASE);
    KINFO("MMU: Kernel MMIO aliases mapped at 0xF0000000 - 0xF02FFFFF\n");

    /* 3. NOUVEAU: Pré-allouer et configurer les temp mappings ICI */
    KINFO("MMU: Setting up temporary mapping slots...\n");
    setup_temp_mapping_slots();
    
    KINFO("MMU: Total sections mapped in TTBR1: %u\n", mapped_sections);
}



/* Configuration du split TTBR */
static void setup_ttbr_split(void)
{
    /* Configuration TTBCR pour split à 2GB */
    uint32_t ttbcr =  get_optimal_ttbcr_n();  /* N=1: 2GB split */
    vaddr_t boundary = get_split_boundary();

    KINFO("MMU: Auto-detected split N=%u, boundary=0x%08X\n", ttbcr, boundary);
    KINFO("MMU: Kernel at 0x%08X -> TTBR%u space\n", 
        (vaddr_t)(uintptr_t)&__start,
        ((vaddr_t)(uintptr_t)&__start >= boundary) ? 1 : 0);
    
    //kprintf("MMU: Configuring TTBCR for 2GB split (N=%d)\n", TTBCR_N_SPLIT_2GB);
    
    /* Set TTBR0 (processus utilisateur - 0-2GB) - NULL au boot */
    set_ttbr0(0x00000000);
    
    /* Set TTBR1 (noyau - 2GB-4GB) */  
    uint32_t ttbr1 = ((uint32_t)kernel_page_dir) | (0b00 << 0) | (1 << 1); // IRGN=0b00 (WBWA), S=0, RGN=0
    set_ttbr1(ttbr1);
    
    /* Set TTBCR */
    ttbcr &= ~(1 << 31);   // EAE = 0 : format court
    set_ttbcr(ttbcr);
    instruction_sync_barrier();

    /* Verify configuration */
    uint32_t ttbr0_check, ttbr1_check, ttbcr_check;
    ttbr0_check = get_ttbr0();
    ttbr1_check = get_ttbr1();
    ttbcr_check = get_ttbcr();
    
    KDEBUG("MMU: TTBR0 = 0x%08X\n", ttbr0_check);
    KDEBUG("MMU: TTBR1 = 0x%08X\n", ttbr1_check);
    KDEBUG("MMU: TTBCR = 0x%08X\n", ttbcr_check);
    
    KINFO("MMU: Split TTBR configuration complete\n");
}

/* Gestion ASID */
static uint32_t allocate_asid(void)
{
    asid_reserve_special();

    for (uint32_t asid = ASID_MIN_USER; asid <= MAX_ASID; asid++) {
        if (!asid_hw_reserved(asid) && !asid_map[asid]) {
            asid_map[asid] = true;
            asid_slot_generation[asid] = asid_generation;
            return asid_make(asid_generation, asid);
        }
    }

    asid_generation++;
    if (asid_generation == 0)
        asid_generation = 1;

    for (uint32_t asid = 0; asid <= MAX_ASID; asid++) {
        asid_map[asid] = false;
        asid_slot_generation[asid] = 0;
    }

    asid_reserve_special();
    flush_all_tlb_local();
    kernel_lifecycle_stats.asid_rollovers++;

    KINFO("MMU: ASID generation rollover -> %u\n", asid_generation);

    for (uint32_t asid = ASID_MIN_USER; asid <= MAX_ASID; asid++) {
        if (!asid_hw_reserved(asid) && !asid_map[asid]) {
            asid_map[asid] = true;
            asid_slot_generation[asid] = asid_generation;
            return asid_make(asid_generation, asid);
        }
    }

    KERROR("MMU: ASID allocation failed after rollover\n");
    return 0;
}

static void free_asid(uint32_t asid)
{
    uint32_t hw_asid = asid_hw(asid);
    uint32_t generation = asid_gen(asid);

    if (!asid_hw_reserved(hw_asid) &&
        asid_map[hw_asid] &&
        asid_slot_generation[hw_asid] == generation) {
        asid_map[hw_asid] = false;
        asid_slot_generation[hw_asid] = 0;
        
        /* Invalider les entrées TLB pour cet ASID */
        tlb_flush_by_asid(hw_asid);
    }
}

void set_current_asid(uint32_t asid)
{
    uint32_t contextidr = asid;
    uint32_t hw_asid = asid_hw(asid);
    
    //KDEBUG("Setting up ASID %d\n", asid);
    /* CONTEXTIDR[7:0] contient l'ASID matériel, le haut sert de génération. */
    //KDEBUG("Setting up contextidr = 0x%08X\n", contextidr);

    /* NOUVEAU: Vérification de cohérence avant écriture */
    uint32_t test_value = contextidr;
    if (test_value != contextidr) {
        KERROR("CONTEXTIDR value corruption detected!\n");
        return;
    }

    //debug_mmu_state();
    
    /* NOUVEAU: Barrières avant l'écriture critique */
    data_sync_barrier();
    instruction_sync_barrier();
    
    /* Écriture sécurisée avec gestion d'erreur */
    //KDEBUG("About to write CONTEXTIDR = 0x%08X\n", contextidr);
    set_contextidr(contextidr);

    //KDEBUG("Wrote CONTEXTIDR = 0x%08X\n", contextidr);
    
    /* Vérification post-écriture */
    uint32_t verify_contextidr = get_contextidr();
    
    if ((verify_contextidr & CONTEXTIDR_ASID_MASK) != hw_asid) {
        KERROR("ASID write failed! Expected hw=%u cookie=%u, got %u\n",
               hw_asid, asid, verify_contextidr & CONTEXTIDR_ASID_MASK);
        return;
    }
    
    
    //KDEBUG("Setting up ASID %d SUCCESSFUL\n", asid);

    current_asid = asid;
}

uint32_t get_current_asid(void)
{
    return get_contextidr();
}

/* Fonctions publiques modifiées pour ASID */

#define TTBR_S     (1u<<1)
#define TTBR_RGN_WBWA (0b01u<<3)     // RGN[4:3]=01
#define TTBR_IRGN_WBWA (1u<<6)       // IRGN[6]=1, IRGN[0]=0 → 01
static inline uint32_t ttbr_attr_wbwa_share(paddr_t base){
    return (base & 0xFFFFC000u) | TTBR_S | TTBR_RGN_WBWA | TTBR_IRGN_WBWA;
}

void switch_address_space(pgdir_t pgdir)
{
    if (!pgdir) {
        KERROR("switch_address_space: NULL pgdir\n");
        return;
    }

    /* Vérifications préalables strictes - adapter pour TTBR0 seulement */
    if (((uint32_t)pgdir & 0x3FFF)) {
        KERROR("Invalid pgdir alignment for switch\n");
        return;
    }

    //KDEBUG("");    // FIX IT
    
    // Charger TTBR0 (base + attributs WBWA + Shareable)
    uint32_t ttbr0 = ttbr_attr_wbwa_share((paddr_t)pgdir);

    /* Changer seulement TTBR0 */
    set_ttbr0(ttbr0);

}

/* Nouvelle fonction pour switch avec ASID */
void switch_address_space_with_asid(pgdir_t pgdir, uint32_t asid)
{
    if (!pgdir) {
        KERROR("switch_address_space_with_asid: NULL pgdir\n");
        return;
    }
    
    /* Vérifier que l'ASID est valide et alloué */
    if (!asid_cookie_valid(asid)) {
        KERROR("Invalid or unallocated ASID cookie: %u (hw=%u gen=%u)\n",
               asid, asid_hw(asid), asid_gen(asid));
        return;
    }

    // Switch vers le contexte kernel pur
    //set_ttbr0((uint32_t)pgdir);  // TTBR0 kernel minimal
    //set_current_asid(asid);      // ASID 

    /* Switch ASID */
    set_current_asid(asid);
    data_sync_barrier();                 // dsb
    instruction_sync_barrier();          // isb

    tlb_shootdown_asid(get_current_asid());
    //set_ttbr0((uint32_t)pgdir);
    data_sync_barrier();
    instruction_sync_barrier();

    /* Switch TTBR0 */
    switch_address_space(pgdir);
    data_sync_barrier();                 // dsb
    instruction_sync_barrier();          // is
    
    //KDEBUG("Address space switched: pgdir=0x%08X, ASID=%u\n", (uint32_t)pgdir, asid);
}

/* Fonctions publiques pour la gestion ASID */
uint32_t vm_allocate_asid(void)
{
    return allocate_asid();
}

void vm_free_asid(uint32_t asid)
{
    free_asid(asid);
}

uint32_t vm_get_current_asid(void)
{
    return get_current_asid();
}

/* Reste des fonctions inchangées... */
static bool is_valid_vaddr(vaddr_t vaddr)
{
    /* Current low-linked kernel and early boot metadata identity window. */
    if (vaddr >= VIRT_RAM_START && vaddr < KERNEL_BOOT_IDENTITY_END) {
        return true;
    }

    /* Kernel direct-map RAM window. */
    if (virt_in_direct_map(vaddr)) {
        return true;
    }
    
    /* Devices/peripherals pour machine virt */
    if (vaddr >= DEVICE_START && vaddr < DEVICE_END) {
        return true;
    }

    /* Verification explicite pour FB_BASE */
    if (vaddr >= FB_BASE && vaddr < (FB_BASE + 0x01000000)) {
        return true;
    }

    /* Espace utilisateur bas (0x00008000 - 0x40000000 pour TTBR0) */
    if (vaddr >= 0x00008000 && vaddr < 0x40000000) {  /* Ajusté pour split 2GB */
        return true;
    }
    
    return false;
}

void map_user_stack(void)
{
    KINFO("MMU: Mapping user stack from 0x%08X to 0x%08X\n", 
            USER_STACK_BOTTOM, USER_STACK_TOP);
    
    /* Lire le TTBR0 actuel (espace utilisateur) */
    uint32_t ttbr0 = get_ttbr0();
    pgdir_cpu_t page_dir = pgdir_cpu_view((pgdir_t)(ttbr0 & 0xFFFFC000));
    
    if (!page_dir) {
        KERROR("MMU: No valid user page directory\n");
        return;
    }
    
    /* Mapper la pile utilisateur section par section (1MB each) dans TTBR0 */
    uint32_t mapped_stack = 0;
    for (vaddr_t addr = USER_STACK_BOTTOM; addr < USER_STACK_TOP; addr += 0x100000) {
        /* Vérifier que c'est dans l'espace TTBR0 (<2GB) */
        if (addr >= 0x40000000) {
            KERROR("MMU: User stack address in kernel space: 0x%08X\n", addr);
            break;
        }
        
        uint32_t index = get_L1_index(addr);
        
        /* Calculer l'adresse physique dans la RAM basse */
        paddr_t phys_addr = VIRT_RAM_START + 0x10000000 + (addr - USER_STACK_BOTTOM);
        
        /* Creer l'entree de section pour utilisateur */
        page_dir[index] = phys_addr |          /* Physical address */
                         0x00000002 |          /* Section bit */
                         0x00000C00 |          /* AP[1:0] = 11 (user r/w) */
                         0x00000004 |          /* Cacheable */
                         0x00000008;           /* Bufferable */
        
        mapped_stack++;
    }
    
    KINFO("MMU: User stack mapped (%u sections) in TTBR0\n", mapped_stack);
    
    /* Invalider le TLB pour les nouvelles mappings */
    tlb_shootdown_all();
}

/* Fonctions inchangées du code original... */
paddr_t allocate_l2_page(bool is_kernel) {
    // Allouer une nouvelle table L2
    void* l2_page = NULL ;
    (void)is_kernel;
    
    //if(is_kernel)
    //    l2_page = allocate_page();
    //else
    //    l2_page = allocate_page();

    l2_page = allocate_page();

    if (!l2_page) {
        KERROR("map_user_page: Failed to allocate L2 table\n");
        return -1;
    }
    //KDEBUG("map_user_page: L2 creation: Allocate Physical Page OK at 0x%08X\n", l2_page);

    //check_address_content(0x48212000, "In allocate_l2_page, before map_temp_page");
    
    // Mapper temporairement pour initialiser
    vaddr_t l2_temp = map_temp_page((paddr_t)l2_page);
    //uint32_t l2_temp = (uint32_t)l2_page;
    if (l2_temp == 0) {
        KERROR("map_user_page: Failed to map L2 table temporarily\n");
        free_page(l2_page);
        return -1;
    }

    //KDEBUG("map_user_page: L2 creation: Map Temp Page OK l2_temp 0x%08X\n", l2_temp);
    
    // Zéroiser la table L2
    //memset((void*)l2_temp, 0, PAGE_SIZE);
    unmap_temp_page((void*)l2_temp);
    
    //KDEBUG("map_user_page: Created L2 table at phys 0x%08X\n", l2_page);

    return (paddr_t)l2_page;
}

void check_address_content(paddr_t phys_addr, const char* step) {
    KDEBUG("check_address_content [%s]: ***********************************************************************\n", step);
    uint8_t* check = (uint8_t*)map_temp_page(phys_addr);
    KDEBUG("check_address_content: %02X %02X %02X %02X\n", check[0], check[1], check[2], check[3]);
    hexdump(check,8);
    unmap_temp_page(check);
    KDEBUG("check_address_content [%s]: ***********************************************************************\n", step);
}

int map_user_page(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid)
{
    return map_user_page_with_perm(pgdir, vaddr, phys_addr, vma_flags, asid, true);
}

int map_user_page_readonly(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid)
{
    return map_user_page_with_perm(pgdir, vaddr, phys_addr, vma_flags, asid, false);
}

int remap_user_page(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid)
{
    return update_user_pte(pgdir, vaddr, phys_addr, vma_flags, asid, true);
}

int set_user_page_readonly(pgdir_t pgdir, vaddr_t vaddr, uint32_t asid)
{
    pte_ptr_t pte = get_user_pte(pgdir, vaddr);
    if (!pte || ((*pte & PTE_TYPE_MASK) == PTE_TYPE_FAULT)) {
        return -ENOENT;
    }

    *pte = (*pte & ~PTE_AP_MASK) | PTE_AP_RW_RO;
    clean_pte_for_mmu(pte);
    tlb_shootdown_page_asid(vaddr, asid);
    return 0;
}

int set_user_page_writable(pgdir_t pgdir, vaddr_t vaddr, uint32_t asid)
{
    pte_ptr_t pte = get_user_pte(pgdir, vaddr);
    if (!pte || ((*pte & PTE_TYPE_MASK) == PTE_TYPE_FAULT)) {
        return -ENOENT;
    }

    *pte = (*pte & ~PTE_AP_MASK) | PTE_AP_RW_RW;
    clean_pte_for_mmu(pte);
    tlb_shootdown_page_asid(vaddr, asid);
    return 0;
}

static int map_user_page_with_perm(pgdir_t pgdir, vaddr_t vaddr,
                                   paddr_t phys_addr, uint32_t vma_flags,
                                   uint32_t asid, bool writable)
{
    if (!pgdir || !is_valid_vaddr(vaddr)) {
        KERROR("Invalid pgdir or vaddr\n");
        return -1;
    }
    
    /* Vérifier que l'adresse est dans l'espace utilisateur TTBR0 (<2GB) */
    if (vaddr >= 0x40000000) {
        KERROR("Address 0x%08X is in kernel space, use kernel mapping functions\n", vaddr);
        return -1;
    }
    
    // Vérifier l'alignement
    if ((phys_addr & 0xFFF) != 0) {
        KERROR("Physical address 0x%08X not page-aligned\n", phys_addr);
        return -1;
    }
    
    if ((vaddr & 0xFFF) != 0) {
        KERROR("Virtual address 0x%08X not page-aligned\n", vaddr);
        return -1;
    }

    uint32_t l1_index = get_L1_index(vaddr);
    uint32_t l2_index = L2_INDEX(vaddr);
    pgdir_cpu_t pgdir_v = pgdir_cpu_view(pgdir);
    l1_entry_t* l1_entry = &pgdir_v[l1_index];
    uint32_t l1_type = *l1_entry & 0x3;
    l2_table_t l2_table;

    if (l1_type == 0x0) {
        paddr_t l2_page = (paddr_t)allocate_page();
        if (!l2_page) {
            return -ENOMEM;
        }
        memset((void *)phys_to_virt(l2_page), 0, PAGE_SIZE);
        *l1_entry = (l2_page & 0xFFFFFC00) | 0x01;
        clean_pte_for_mmu(l1_entry);
        tlb_shootdown_page_asid(vaddr, asid);
    } else if (l1_type == 0x2) {
        KERROR("map_user_page: refusing L1 section at user vaddr 0x%08X\n", vaddr);
        return -EEXIST;
    } else if (l1_type != 0x1) {
        KERROR("map_user_page: Unsupported L1 type %u for vaddr 0x%08X\n",
               l1_type, vaddr);
        return -EINVAL;
    }

    l2_table = (l2_table_t)phys_to_virt((paddr_t)(*l1_entry & 0xFFFFFC00));
    uint32_t existing_entry = l2_table[l2_index];
    if ((existing_entry & 0x3) != 0) {
        paddr_t existing_paddr = existing_entry & 0xFFFFF000;
        if (existing_paddr == phys_addr) {
            return 0;
        }
        KERROR("map_user_page: vaddr 0x%08X already maps 0x%08X, requested 0x%08X\n",
               vaddr, existing_paddr, phys_addr);
        return -EEXIST;
    }

    uint32_t page_flags = user_page_flags(vma_flags, writable);

    l2_table[l2_index] = (phys_addr & 0xFFFFF000) | page_flags;
    clean_pte_for_mmu(&l2_table[l2_index]);
    tlb_shootdown_page_asid(vaddr, asid);
    if (vma_flags & VMA_EXEC) {
        sync_icache_for_exec();
    }
    return 0;
}

uint32_t get_L1_index(vaddr_t vaddr){
    return vaddr >= get_split_boundary() ? KERNEL_L1_INDEX(vaddr) : vaddr >> 20 ; 
}

paddr_t get_physical_address(pgdir_t pgdir, vaddr_t vaddr) {
    return get_phys_addr_from_pgdir(pgdir, vaddr);
}


void invalidate_tlb_all(void)
{
    tlb_shootdown_all();
}

void invalidate_tlb_page(vaddr_t vaddr)
{
    tlb_shootdown_page(vaddr);
}

void invalidate_tlb_page_asid(vaddr_t vaddr, uint32_t asid)
{
    tlb_shootdown_page_asid(vaddr, asid);
}

void invalidate_tlb_asid(uint32_t asid)
{
    tlb_shootdown_asid(asid);
}

uint32_t get_ttbr0(void)
{
    return arm_read_ttbr0();
}

void set_ttbr0(uint32_t ttbr0)
{
    arm_write_ttbr0(ttbr0);
}

pgdir_cpu_t get_kernel_pgdir(void)
{
    return kernel_pgdir;
}

pgdir_cpu_t get_kernel_ttbr0(void)
{
    return ttbr0_pgdir;
}

/* Fonctions de debug mises à jour */
void debug_mmu_state(void)
{
    uint32_t ttbr0 = get_ttbr0();
    uint32_t ttbr1 = get_ttbr1();
    uint32_t ttbcr = get_ttbcr();
    uint32_t contextidr = get_contextidr() ;
    uint32_t sctlr = get_sctlr();
    uint32_t dacr = get_dacr();
    
    KDEBUG("=== MMU SPLIT TTBR STATE DEBUG ===\n");
    KDEBUG("kernel_page_dir:      %p\n", kernel_page_dir);
    KDEBUG("TTBR0 register:       0x%08X (user space)\n", ttbr0);
    KDEBUG("TTBR1 register:       0x%08X (kernel space)\n", ttbr1);
    KDEBUG("TTBCR register:       0x%08X (N=%d)\n", ttbcr, ttbcr & 0x7);
    KDEBUG("CONTEXTIDR:           0x%08X (ASID=%d)\n", contextidr, contextidr & ASID_MASK);
    KDEBUG("Current ASID:         cookie=%u hw=%u gen=%u\n",
           current_asid, asid_hw(current_asid), asid_gen(current_asid));
    KDEBUG("SCTLR Register:       0x%08X\n", sctlr);
    KDEBUG("DACR Register:        0x%08X\n", dacr);
     
    /* Vérifications de cohérence */
    if (kernel_pgdir == kernel_page_dir) {
        KDEBUG("OK kernel_pgdir correctly points to kernel_page_dir\n");
    } else {
        KERROR("KO kernel_pgdir != kernel_page_dir\n");
    }
    
    if ((uint32_t)kernel_page_dir == (ttbr1 & 0xFFFFC000)) {
        KDEBUG("OK TTBR1 correctly points to kernel_page_dir\n");
    } else {
        KERROR("KO TTBR1 != kernel_page_dir address\n");
    }
    
    //uint32_t split_size = 4096 >> (ttbcr & 0x7);  // En MB
    //KDEBUG("Memory split: 0--%uMB (TTBR0), %uMB--4GB (TTBR1)\n", 
    //       split_size * 1024, split_size * 1024);
    
    KDEBUG("=== END MMU SPLIT DEBUG ===\n");
}

/* Reste des fonctions debug inchangées... */
void debug_kernel_stack_integrity(const char* location)
{
    extern uint32_t __stack_bottom, __stack_top;
    task_t *task = task_current_local();
    
    vaddr_t current_sp = arm_current_sp();
    
    KDEBUG("=== STACK CHECK [%s] ===\n", location);
    
    // Detecter si on est dans une pile de tache
    bool in_task_stack = false;
    if (task && task->stack_base) {
        vaddr_t task_stack_bottom = (vaddr_t)(uintptr_t)task->stack_base;
        vaddr_t task_stack_top = task_stack_bottom + task->stack_size;
        
        if (current_sp >= task_stack_bottom && current_sp <= task_stack_top) {
            in_task_stack = true;
            
            KDEBUG("CONTEXT: Task '%s' stack\n", task->name);
            KDEBUG("Task stack bottom: 0x%08X\n", task_stack_bottom);
            KDEBUG("Task stack top:    0x%08X\n", task_stack_top);
            KDEBUG("Task stack size:   %u bytes (%u KB)\n", 
                   task->stack_size, task->stack_size / 1024);
            KDEBUG("Current SP:        0x%08X\n", current_sp);
            
            uint32_t used = (uint32_t)(task_stack_top - current_sp);
            uint32_t free = (uint32_t)(current_sp - task_stack_bottom);
            KDEBUG("OK SP in valid TASK range\n");
            KDEBUG("   Stack used:  %u bytes\n", used);
            KDEBUG("   Stack free:  %u bytes\n", free);
            
            if (used > (task->stack_size * 3/4)) {
                KWARN("WARNING  Task stack usage high: %u/%u bytes (%u%%)\n", 
                      used, task->stack_size,
                      used * 100 / task->stack_size);
            }
        }
    }
    
    if (!in_task_stack) {
        // Verification pile kernel principale
        vaddr_t stack_bottom = (vaddr_t)(uintptr_t)&__stack_bottom;
        vaddr_t stack_top = (vaddr_t)(uintptr_t)&__stack_top;
        uint32_t stack_size = (uint32_t)(stack_top - stack_bottom);
        
        KDEBUG("CONTEXT: Kernel main stack\n");
        KDEBUG("Kernel stack bottom: 0x%08X\n", stack_bottom);
        KDEBUG("Kernel stack top:    0x%08X\n", stack_top);
        KDEBUG("Kernel stack size:   %u bytes (%u KB)\n", stack_size, stack_size / 1024);
        KDEBUG("Current SP:          0x%08X\n", current_sp);
        
        if (current_sp < stack_bottom) {
            KERROR("KO SP UNDERFLOW! SP below kernel stack bottom\n");
            KERROR("   Underflow by: %u bytes\n", (uint32_t)(stack_bottom - current_sp));
        } else if (current_sp >= stack_top) {
            KERROR("KO SP OVERFLOW! SP above kernel stack top\n"); 
            KERROR("   Overflow by: %u bytes\n", (uint32_t)(current_sp - stack_top));
        } else {
            uint32_t used = (uint32_t)(stack_top - current_sp);
            uint32_t free = (uint32_t)(current_sp - stack_bottom);
            KDEBUG("OK SP in valid KERNEL range\n");
            KDEBUG("   Stack used:  %u bytes\n", used);
            KDEBUG("   Stack free:  %u bytes\n", free);
            
            if (free < 512) {
                KWARN("WARNING WARNING: Less than 512 bytes free!\n");
            }
        }
    }
    
    KDEBUG("===============================\n");
}

void check_memory_corruption(void)
{
    extern uint32_t __start, __end;
    extern uint32_t __bss_start, __bss_end;
    vaddr_t kernel_start = (vaddr_t)(uintptr_t)&__start;
    vaddr_t kernel_end = (vaddr_t)(uintptr_t)&__end;
    vaddr_t bss_start = (vaddr_t)(uintptr_t)&__bss_start;
    vaddr_t bss_end = (vaddr_t)(uintptr_t)&__bss_end;
    
    KDEBUG("=== MEMORY LAYOUT CHECK ===\n");
    KDEBUG("Kernel start:  0x%08X\n", kernel_start);
    KDEBUG("Kernel end:    0x%08X\n", kernel_end);
    KDEBUG("BSS start:     0x%08X\n", bss_start);
    KDEBUG("BSS end:       0x%08X\n", bss_end);
    
    /* Verifier que les adresses sont coherentes */
    if (kernel_start > kernel_end) {
        KERROR("KO Kernel start > end!\n");
    }
    
    if (bss_start > bss_end) {
        KERROR("KO BSS start > end!\n");
    }
    
    //KDEBUG("MMU start:     0x%08X\n", (uint32_t)&__mmu_tables_start);
    //KDEBUG("MMU end:       0x%08X\n", (uint32_t)&__mmu_tables_end);


    /* Verifier le heap */
    extern uint8_t* heap_base;
    extern size_t heap_size;
    
    if (heap_base) {
        vaddr_t heap_start = (vaddr_t)(uintptr_t)heap_base;
        KDEBUG("Heap base:     0x%08X\n", heap_start);
        KDEBUG("Heap size:     %u bytes\n", heap_size);
        KDEBUG("Heap end:      0x%08X\n", heap_start + heap_size);
    }
}

void dump_kernel_stack(int depth)
{
    vaddr_t current_sp;
    current_sp = arm_current_sp();
    
    KDEBUG("=== KERNEL STACK DUMP ===\n");
    KDEBUG("SP: 0x%08X\n", current_sp);
    
    uint32_t* stack_ptr = (uint32_t*)current_sp;
    
    for (int i = 0; i < depth && i < 16; i++) {
        vaddr_t addr = (vaddr_t)(uintptr_t)(stack_ptr + i);
        if (IS_KERNEL_ADDR(addr)) {
            KDEBUG("[SP+%02d] 0x%08X: 0x%08X\n", 
                   i * 4, addr, stack_ptr[i]);
        } else {
            KDEBUG("[SP+%02d] INVALID ADDRESS\n", i * 4);
            break;
        }
    }
}

void setup_svc_stack(void) {
    extern uint32_t __svc_stack_top;
    
    // Vérifier que MMU est active
    uint32_t sctlr = get_sctlr();
    if (!(sctlr & 1)) {
        KERROR("Setting up SVC stack before MMU!\n");
        return;
    }
    
    vaddr_t svc_sp = ((vaddr_t)(uintptr_t)&__svc_stack_top) & ~7u;
    KINFO("Configuring SVC stack at 0x%08X\n", svc_sp);
    
    arm_set_sp(svc_sp);
    KINFO("SVC stack configured successfully\n");
}

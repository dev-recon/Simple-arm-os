/* kernel/memory/mmu.c - Version avec split TTBR et ASID pour Cortex-A15 */
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>
#include <kernel/debug_print.h>
#include <kernel/display.h>
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
static uint32_t kernel_page_dir[4096] __attribute__((section(".data"), aligned(16384)));  /* TTBR1 */
static uint32_t kernel_ttbr0[4096] __attribute__((section(".data"), aligned(16384)));  /* TTBR1 */; /* TTBR0 */

/* Pointeurs globaux */
uint32_t* kernel_pgdir = kernel_page_dir;   /* TTBR1 - Espace noyau */
uint32_t* ttbr0_pgdir = kernel_ttbr0;   /* TTBR0 - Espace noyau */

/* Gestion ASID */
static uint32_t current_asid = 1;  /* ASID 0 réservé au noyau */
bool asid_map[MAX_ASID + 1] = {true}; /* ASID 0 réservé */

extern void vectors(void);

/* Nouvelles fonctions pour la gestion ASID */
static uint32_t allocate_asid(void);
static void free_asid(uint32_t asid);
void set_current_asid(uint32_t asid);
uint32_t get_current_asid(void);
static void setup_ttbr_split(void);
static void setup_kernel_space(void);
static void setup_user_template(void);
uint32_t allocate_l2_page(bool is_kernel);
void check_address_content(uint32_t phys_addr, const char* step);



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
    
    //uint32_t ttbr0_phys_addr = (uint32_t)ttbr0_phys_page;
    
    //KDEBUG("TTBR0 table physical address: 0x%08X\n", ttbr0_phys_addr);
    
    /* Vérifier l'alignement 4KB requis pour les tables de pages ARM */
    //if (ttbr0_phys_addr & 0xFFF) {
         /* Forcer l'alignement si nécessaire */
        //uint32_t aligned_addr = (ttbr0_phys_addr + 0xFFF) & ~0xFFF;
        //uint32_t aligned_addr = (ttbr0_phys_addr + 0x3FFF) & ~0x3FFF;

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

void dump_l1( uint32_t va) {
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
    uint32_t kernel_start = (uint32_t)&__start;
    
    // Déterminer le split optimal basé sur où se trouve le noyau
    if (kernel_start >= 0xC0000000) return 2;  // N=2: split 3GB (noyau à 3GB+)
    if (kernel_start >= 0x80000000) return 1;  // N=1: split 2GB (noyau à 2GB+) 
    if (kernel_start >= 0x40000000) return 2;  // N=0: split 1GB (noyau à 1GB+)
    
    // Si noyau < 1GB, pas de split TTBR (utiliser TTBR0 uniquement)
    return 7;  // Valeur d'erreur
}


uint32_t get_split_boundary(void)
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
            kprintf("MMU: Quick test found %s of RAM\n", quick_tests[i].name);
            return quick_tests[i].size_mb * 1024 * 1024;
        }
    }
    
    kprintf("MMU: Quick test failed, using 1GB fallback\n");
    return 1024 * 1024 * 1024;
}

void configure_alignment_policy(void) {
    uint32_t sctlr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r" (sctlr));
    
    kprintf("Current SCTLR = 0x%08X\n", sctlr);
    kprintf("Alignment checking: %s\n", (sctlr & (1<<1)) ? "ENABLED" : "DISABLED");
    
    // Desactiver l'alignement strict
    sctlr &= ~(1 << 1);  // Clear A bit
    
    __asm__ volatile("mcr p15, 0, %0, c1, c0, 0" : : "r" (sctlr));
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
    
    kprintf("Alignment checking disabled OK\n");
}

void check_endianness() {
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};

    kprintf("Endianness test:\n");
    kprintf("  32-bit integer value: 0x%08X\n", bint.i);
    kprintf("  Byte order:   %02X %02X %02X %02X\n", 
            bint.c[0], bint.c[1], bint.c[2], bint.c[3]);

    if (bint.c[0] == 0x01) {
        kprintf("  System is BIG ENDIAN\n");
    } else if (bint.c[0] == 0x04) {
        kprintf("  System is LITTLE ENDIAN\n");
    } else {
        kprintf("  Unexpected endianness!\n");
    }

    // Vérification spécifique ARM
    uint32_t cpsr;
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    bool ee_bit = (cpsr & (1 << 9)) != 0;
    kprintf("  CPSR Endian Exception bit: %s\n", 
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
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 0" :: "r"(ttbr0_value));  // TTBR0
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" :: "r"(ttbr1_value));  // TTBR1

    // TTBCR : N = 2 (split à 0x40000000), EAE = 0 (format court)
    uint32_t ttbcr = 0x2; //0x2;
    ttbcr_value = ttbcr;
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 2" :: "r"(ttbcr_value));

    __asm__ volatile("dsb");
    __asm__ volatile("isb");

// Vérifier immédiatement
uint32_t ttbcr_check;
__asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr_check));
KDEBUG("TTBCR written: 0x%08X, read back: 0x%08X\n", ttbcr_value, ttbcr_check);

if (ttbcr_check != ttbcr_value) {
    KERROR("TTBCR write failed!\n");
    KERROR("  Written: 0x%08X\n", ttbcr_value);
    KERROR("  Read:    0x%08X\n", ttbcr_check);
    while(1);
}

    // Synchronisation
    __asm__ volatile("dsb");
    __asm__ volatile("isb");

    /* === Invalider TLB et caches === */
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" :: "r"(0));  // Invalidate TLB
    __asm__ volatile("mcr p15, 0, %0, c7, c7, 0" :: "r"(0));  // Invalidate caches
    __asm__ volatile("dsb");
    __asm__ volatile("isb");

    /* === DACR (Domain Access Control) === */
    uint32_t dacr = 0x55555555;
    __asm__ volatile("mcr p15, 0, %0, c3, c0, 0" :: "r"(dacr));

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

    uint32_t next_pc;
    __asm__ volatile("add %0, pc, #16" : "=r"(next_pc));

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
__asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(check_ttbr0));
__asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(check_ttbr1));
__asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(check_ttbcr));

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
    __asm__ volatile("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));
    __asm__ volatile("dsb");
    __asm__ volatile("isb");

    KDEBUG("MMU ACTIVATED .....\n");

    KDEBUG("MMU: Post-activation test 1");
    
    /* Verify MMU is enabled */
    uint32_t sctlr_final;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr_final));
    debug_print_hex("MMU: Final SCTLR = ", sctlr_final);

    // Reconfigurer VBAR apres MMU ON
    uint32_t vbar_addr = (uint32_t)&vectors;
    __asm__ volatile("mcr p15, 0, %0, c12, c0, 0" :: "r"(vbar_addr));
    __asm__ volatile("dsb");
    __asm__ volatile("isb");

    // Activer les exceptions
    __asm__ volatile ("cpsie aif");

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



static void setup_kernel_space(void)
{
    uint32_t split_boundary = get_split_boundary();  // 0x40000000 avec N=2
    uint32_t initial_ram_size = 1024 * 1024 * 1024;
    uint32_t ram_end = VIRT_RAM_START + initial_ram_size;  // 0x80000000
    uint32_t mapped_sections = 0;
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
     for (uint32_t addr = 0; addr < split_boundary; addr += 0x100000) {
        uint32_t index = get_L1_index(addr);  // Index 0-1023
        //kernel_page_dir[index] = addr | 0xC0E;
        ttbr0_pgdir[index] = addr | 0xC0E;
        mapped_low++;
    }

    kprintf("Mapped low memory (TTBR0): 0x0 - 0x40000000 - %u sections\n", mapped_low);

    /* Map device space */
    for (uint32_t addr = DEVICE_START; addr < DEVICE_END; addr += 0x100000) {

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

    kprintf("Mapped devices sections (TTBR0-TTBR1): 0x0 - 0x40000000 - %u sections\n", mapped_devices);
    
    /* Map kernel/RAM space - seulement les sections >= split_boundary pour TTBR1 */
    for (uint32_t addr = split_boundary; addr < ram_end; addr += 0x100000) {

                // TTBR1 pointe sur &kernel_page_dir[1024], donc :
        // - Index 0 de TTBR1 = kernel_page_dir[1024] = adresse 0x40000000
        // - Index 1 de TTBR1 = kernel_page_dir[1025] = adresse 0x40100000
        uint32_t ttbr1_index = get_L1_index(addr);

        /* Skip la zone réservée aux mappings temporaires */
        if (addr >= TEMP_MAPPING_START && addr < TEMP_MAPPING_END) {
            continue;
        }
       
        kernel_page_dir[ttbr1_index] = addr |           
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */

        mapped_sections++;
    }
    
    //kprintf("MMU: Kernel RAM sections mapped: %u\n", mapped_sections);

    kprintf("MMU: Kernel RAM sections mapped before temp area: %u\n", mapped_sections);

    /* 3. NOUVEAU: Pré-allouer et configurer les temp mappings ICI */
    kprintf("MMU: Setting up temporary mapping slots...\n");
    setup_temp_mapping_slots();
    
    /* 4. Map le reste de l'espace kernel après la zone temp */
    for (uint32_t addr = TEMP_MAPPING_END; addr < ram_end; addr += 0x100000) {
        uint32_t ttbr1_index = get_L1_index(addr);
        
        kernel_page_dir[ttbr1_index] = addr |           
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */
        mapped_sections++;
    }
    
    
    kprintf("MMU: Total sections mapped in TTBR1: %u\n", mapped_sections);
}



/* Configuration du split TTBR */
static void setup_ttbr_split(void)
{
    /* Configuration TTBCR pour split à 2GB */
    uint32_t ttbcr =  get_optimal_ttbcr_n();  /* N=1: 2GB split */
    uint32_t boundary = get_split_boundary();

    kprintf("MMU: Auto-detected split N=%u, boundary=0x%08X\n", ttbcr, boundary);
    kprintf("MMU: Kernel at 0x%08X -> TTBR%u space\n", 
        (uint32_t)&__start, ((uint32_t)&__start >= boundary) ? 1 : 0);
    
    //kprintf("MMU: Configuring TTBCR for 2GB split (N=%d)\n", TTBCR_N_SPLIT_2GB);
    
    /* Set TTBR0 (processus utilisateur - 0-2GB) - NULL au boot */
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 0" : : "r"(0x00000000));
    
    /* Set TTBR1 (noyau - 2GB-4GB) */  
    uint32_t ttbr1 = ((uint32_t)kernel_page_dir) | (0b00 << 0) | (1 << 1); // IRGN=0b00 (WBWA), S=0, RGN=0
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" : : "r"(ttbr1));
    
    /* Set TTBCR */
    ttbcr &= ~(1 << 31);   // EAE = 0 : format court
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 2" : : "r"(ttbcr));
    __asm__ volatile("isb");

    /* Verify configuration */
    uint32_t ttbr0_check, ttbr1_check, ttbcr_check;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0_check));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1_check));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr_check));
    
    debug_print_hex("MMU: TTBR0 = ", ttbr0_check);
    debug_print_hex("MMU: TTBR1 = ", ttbr1_check); 
    debug_print_hex("MMU: TTBCR = ", ttbcr_check);
    
    kprintf("MMU: Split TTBR configuration complete\n");
}

/* Gestion ASID */
static uint32_t allocate_asid(void)
{
    asid_map[0] = true;  /* ASID 0 reste réservé */
    asid_map[ASID_KERNEL] = true;

    for (uint32_t asid = 1; asid <= MAX_ASID; asid++) {
        if (!asid_map[asid]) {
            asid_map[asid] = true;
            return asid;
        }
    }
    
    /* Si tous les ASID sont utilisés, faire un flush global et recommencer */
    kprintf("MMU: All ASIDs in use, performing global TLB flush\n");
    
    /* Invalider tout le TLB et réinitialiser la carte ASID */
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0));  /* TLBIALL */
    memset(asid_map, false, sizeof(asid_map));
    asid_map[0] = true;  /* ASID 0 reste réservé */
    asid_map[ASID_KERNEL] = true;
    return 1;
}

static void free_asid(uint32_t asid)
{
    if (asid > 0 && asid < MAX_ASID) {
        asid_map[asid] = false;
        
        /* Invalider les entrées TLB pour cet ASID */
        __asm__ volatile("mcr p15, 0, %0, c8, c7, 2" : : "r"(asid));  /* TLBIASID */
        //asm volatile("mcr p15, 0, %0, c8, c7, 0" :: "r"(0));  // TLBIALL
        data_sync_barrier();
        instruction_sync_barrier();
    }
}

void set_current_asid(uint32_t asid)
{
    uint32_t contextidr;
    
    //KDEBUG("Setting up ASID %d\n", asid);
    /* Lire le CONTEXTIDR actuel */
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));

    //KDEBUG("Current contextidr = 0x%08X\n", contextidr);
    
    /* Mettre à jour seulement les bits ASID (bits 7:0) */
    contextidr = (contextidr & ~CONTEXTIDR_ASID_MASK) | (asid & CONTEXTIDR_ASID_MASK);
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
   
    __asm__ volatile(
        "mcr p15, 0, %0, c13, c0, 1 \n"
        "nop                        \n"
        "nop                        \n"
        "nop                        \n"
        "nop                        \n"
        "isb                        \n"
        :
        : "r"(contextidr)
        : "memory"
    );

    //KDEBUG("Wrote CONTEXTIDR = 0x%08X\n", contextidr);
    
    /* Vérification post-écriture */
    uint32_t verify_contextidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(verify_contextidr));
    
    if ((verify_contextidr & 0xFF) != asid) {
        KERROR("ASID write failed! Expected %u, got %u\n", asid, verify_contextidr & 0xFF);
        return;
    }
    
    
    //KDEBUG("Setting up ASID %d SUCCESSFUL\n", asid);

    current_asid = asid;
}

uint32_t get_current_asid(void)
{
    uint32_t contextidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    return contextidr & CONTEXTIDR_ASID_MASK;
}

/* Fonctions publiques modifiées pour ASID */

#define TTBR_S     (1u<<1)
#define TTBR_RGN_WBWA (0b01u<<3)     // RGN[4:3]=01
#define TTBR_IRGN_WBWA (1u<<6)       // IRGN[6]=1, IRGN[0]=0 → 01
static inline uint32_t ttbr_attr_wbwa_share(uint32_t base){
    return (base & 0xFFFFC000u) | TTBR_S | TTBR_RGN_WBWA | TTBR_IRGN_WBWA;
}

void switch_address_space(uint32_t* pgdir)
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
    uint32_t ttbr0 = ttbr_attr_wbwa_share((uint32_t)pgdir);

    /* Changer seulement TTBR0 */
    set_ttbr0(ttbr0);

}

/* Nouvelle fonction pour switch avec ASID */
void switch_address_space_with_asid(uint32_t* pgdir, uint32_t asid)
{
    if (!pgdir) {
        KERROR("switch_address_space_with_asid: NULL pgdir\n");
        return;
    }
    
    /* Vérifier que l'ASID est valide et alloué */
    if (asid > MAX_ASID || !asid_map[asid]) {
        KERROR("Invalid or unallocated ASID: %u\n", asid);
        return;
    }

    // Switch vers le contexte kernel pur
    //set_ttbr0((uint32_t)pgdir);  // TTBR0 kernel minimal
    //set_current_asid(asid);      // ASID 

    /* Switch ASID */
    set_current_asid(asid);
    data_sync_barrier();                 // dsb
    instruction_sync_barrier();          // isb

    invalidate_tlb_asid(get_current_asid());
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
static bool is_valid_vaddr(uint32_t vaddr)
{
    /* RAM kernel/user pour machine virt */
    if (vaddr >= VIRT_RAM_START && vaddr < (uint32_t)VIRT_RAM_END) {
        return true;
    }
    
    /* Devices/peripherals pour machine virt */
    if (vaddr >= DEVICE_START && vaddr < (uint32_t)DEVICE_END) {
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
    kprintf("MMU: Mapping user stack from 0x%08X to 0x%08X\n", 
            USER_STACK_BOTTOM, USER_STACK_TOP);
    
    /* Lire le TTBR0 actuel (espace utilisateur) */
    uint32_t ttbr0 = get_ttbr0();
    uint32_t* page_dir = (uint32_t*)(ttbr0 & 0xFFFFC000);
    
    if (!page_dir) {
        kprintf("MMU: ERROR - No valid user page directory\n");
        return;
    }
    
    /* Mapper la pile utilisateur section par section (1MB each) dans TTBR0 */
    uint32_t mapped_stack = 0;
    for (uint32_t addr = USER_STACK_BOTTOM; addr < USER_STACK_TOP; addr += 0x100000) {
        /* Vérifier que c'est dans l'espace TTBR0 (<2GB) */
        if (addr >= 0x40000000) {
            kprintf("MMU: ERROR - User stack address in kernel space: 0x%08X\n", addr);
            break;
        }
        
        uint32_t index = get_L1_index(addr);
        
        /* Calculer l'adresse physique dans la RAM basse */
        uint32_t phys_addr = VIRT_RAM_START + 0x10000000 + (addr - USER_STACK_BOTTOM);
        
        /* Creer l'entree de section pour utilisateur */
        page_dir[index] = phys_addr |          /* Physical address */
                         0x00000002 |          /* Section bit */
                         0x00000C00 |          /* AP[1:0] = 11 (user r/w) */
                         0x00000004 |          /* Cacheable */
                         0x00000008;           /* Bufferable */
        
        mapped_stack++;
    }
    
    kprintf("MMU: User stack mapped (%u sections) in TTBR0\n", mapped_stack);
    
    /* Invalider le TLB pour les nouvelles mappings */
    invalidate_tlb_all();
}

/* Fonctions inchangées du code original... */
uint32_t allocate_l2_page(bool is_kernel) {
    // Allouer une nouvelle table L2
    void* l2_page = NULL ;
    
    if(is_kernel)
        l2_page = allocate_page();
    else
        l2_page = allocate_page();

    if (!l2_page) {
        KERROR("map_user_page: Failed to allocate L2 table\n");
        return -1;
    }
    //KDEBUG("map_user_page: L2 creation: Allocate Physical Page OK at 0x%08X\n", l2_page);

    //check_address_content(0x48212000, "In allocate_l2_page, before map_temp_page");
    
    // Mapper temporairement pour initialiser
    uint32_t l2_temp = map_temp_page((uint32_t)l2_page);
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

    return (uint32_t)l2_page;
}

void check_address_content(uint32_t phys_addr, const char* step) {
    KDEBUG("check_address_content [%s]: ***********************************************************************\n", step);
    uint8_t* check = (uint8_t*)map_temp_page((uint32_t)phys_addr);
    KDEBUG("check_address_content: %02X %02X %02X %02X\n", check[0], check[1], check[2], check[3]);
    hexdump(check,8);
    unmap_temp_page(check);
    KDEBUG("check_address_content [%s]: ***********************************************************************\n", step);
}

int map_user_page(uint32_t* pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags, uint32_t asid)
{
    //KDEBUG("map_user_page: pgdir=0x%08X, vaddr=0x%08X, paddr=0x%08X, flags=0x%08X, asid=%u\n", pgdir,
    //       vaddr, phys_addr, vma_flags, asid);
    
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

    uint32_t saved_asid = get_current_asid();
    if(saved_asid != asid)
        set_current_asid(asid);

    uint32_t existing_paddr = get_physical_address(pgdir, vaddr);
    if (existing_paddr == phys_addr) {
        KDEBUG("map_user_page: Page already mapped correctly, skipping\n");
        return 0;
    } else if (existing_paddr != 0) {
        KERROR("map_user_page: Page mapped to different physical address!\n");
        KERROR("  vaddr=0x%08X, existing=0x%08X, requested=0x%08X\n", 
               vaddr, existing_paddr, phys_addr);
        return -1;
    }

    //KDEBUG("map_user_page: pgdir=0x%08X, vaddr=0x%08X, paddr=0x%08X, flags=0x%08X\n", 
    //       pgdir, vaddr, phys_addr, vma_flags);
    
    //KDEBUG("map_user_page: VMA flags: R%s W%s X%s\n",
    //       (vma_flags & VMA_READ) ? "+" : "-",
    //       (vma_flags & VMA_WRITE) ? "+" : "-",
    //       (vma_flags & VMA_EXEC) ? "+" : "-");
    
    // Utiliser des pages de 4KB
    uint32_t l1_index = get_L1_index(vaddr);        // Bits 31-20
    uint32_t l2_index = L2_INDEX(vaddr); // Bits 19-12
    
    //KDEBUG("map_user_page: L1 index: %u, L2 index: %u\n", l1_index, l2_index);
    
    // Vérifier/créer la table L2
    uint32_t* l1_entry = &pgdir[l1_index];
    uint32_t* l2_table = NULL;
    
    if (!(*l1_entry & 0x1)) {

        //check_address_content(phys_addr, "Before allocate_l2_page");
        // Allouer une nouvelle table L2
        uint32_t l2_page = (uint32_t)allocate_page() ;
        //check_address_content(phys_addr, "After allocate_l2_page");
        
        // Configurer l'entrée L1 style Cortex-A15
        *l1_entry = (l2_page & 0xFFFFFC00) | 0x01;  // Coarse page table

        asm volatile("mcr p15,0,%0,c7,c10,1" :: "r"(l1_entry) : "memory"); // DCCMVAC
        asm volatile("dsb ishst");
        asm volatile("mcr p15,0,%0,c8,c3,1" :: "r"(vaddr & ~0xFFF) : "memory"); // TLBIMVAIS
        asm volatile("dsb ish; isb");

        //KDEBUG("map_user_page: L1 Entry Address=0x%08X, L1 Entry Value = 0x%08X\n", l1_entry, *l1_entry);
    }

    //KDEBUG("L1 test: !(*l1_entry & 0x1) failed\n");
    
    //check_address_content(phys_addr, "Before map_temp_page");

    // Obtenir l'adresse de la table L2
    uint32_t l2_phys = *l1_entry & 0xFFFFFC00;
    uint32_t l2_temp = l2_phys;
    //uint32_t l2_temp = map_temp_page_large(l2_phys, 12*1024);
    if (l2_temp == 0) {
        KERROR("map_user_page: Failed to map existing L2 table\n");
        return -1;
    }
    
    l2_table = (uint32_t*)l2_temp;
    
    // Déterminer les permissions ARM
    uint32_t page_flags = 0x02;  // Small page type

    // TOUJOURS mettre AP[2] = 1 pour accès user (bit [9])
    //page_flags |= 0x200;  // AP[2] = 1 (bit [9])

    page_flags |= 0x0C;
    
    // Permissions d'accès
    if (vma_flags & VMA_WRITE) {
        page_flags |= 0x30;  // AP[1:0] = 11 (user R/W)
    } else {
        page_flags |= 0x20;  // AP[1:0] = 10 (user R/O) 
    }
    
    // Execute Never bit
    if (!(vma_flags & VMA_EXEC)) {
        page_flags |= 0x01;  // XN bit
        sync_icache_for_exec();
    }
    
    // Cache/Buffer pour RAM
    //if (vaddr >= VIRT_RAM_START && vaddr < VIRT_RAM_END) {
    //    page_flags |= 0x0C;  // Cacheable + Bufferable
    //}
    
    //KDEBUG("map_user_page: ARM page flags: 0x%08X\n", page_flags);
    
    // Configurer l'entrée L2
    l2_table[l2_index] = (phys_addr & 0xFFFFF000) | page_flags;

    // 1) Clean D-cache ligne contenant la PTE L2, par son **adresse VA de la PTE**
    void *pte_l2_va = &l2_table[l2_index];
    asm volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(pte_l2_va) : "memory"); // DCCMVAC

    // 2) Barrière avant invalidation TLB
    asm volatile("dsb ishst" ::: "memory");

    // 3) Invalider la traduction de vaddr dans le TLB (ASID courant = asid)
    asm volatile("mcr p15, 0, %0, c8, c3, 1" :: "r"(vaddr & ~0xFFF) : "memory"); // TLBIMVAIS

    // 4) Barrières de fin
    asm volatile("dsb ish; isb" ::: "memory");

    data_sync_barrier();    // Assure visibilité avant TLB flush
    instruction_sync_barrier();

    //KDEBUG("map_user_page: Final L2 flags: 0x%08X (vaddr=0x%08X)\n", page_flags, vaddr);
    
    //KDEBUG("map_user_page: L2[%u] = 0x%08X\n", l2_index, l2_table[l2_index]);
    
    // Unmap la table L2
    //KDEBUG("map_user_page: Wrote L2[%d] = 0x%08X\n", l2_index, l2_table[l2_index]);
    //unmap_temp_page((void*)l2_temp);
    
    // Invalider le TLB pour cette adresse avec ASID
    if (get_current_asid() != asid) {
        KERROR("map_user_page: !!! Invalidation TLB with wrong ASID !!!\n");
    }
    invalidate_tlb_page_asid(vaddr, asid);
    //invalidate_tlb_page_asid(vaddr, get_current_asid());

    asm volatile("dsb ish" ::: "memory");
    asm volatile("mcr p15, 0, %0, c8, c3, 0" :: "r"(0)); // TLBIALLIS
    asm volatile("dsb ish; isb" ::: "memory");

    uint32_t pa_out = 0;
    uint32_t par_out = 0;
    ats1cpr_probe(vaddr, &pa_out, &par_out);

    //KINFO("map_user_page: ats1cpr_probe 0x%08X -> pa_out 0x%08X -> par_out 0x%08X\n", vaddr, pa_out, par_out);


    data_sync_barrier();
    instruction_sync_barrier();
    if(saved_asid != asid)
        set_current_asid(saved_asid);

        // Si exécutable, purge I-cache PoU après les TLBIs
    if (vma_flags & VMA_EXEC) {
        asm volatile("mcr p15,0,%0,c7,c5,0"::"r"(0)); // ICIALLU
        asm volatile("dsb ish; isb");
    }
    
    //KINFO("map_user_page: Successfully mapped page 0x%08X -> 0x%08X -> asid %d\n", vaddr, phys_addr, asid);
    return 0;
}

void map_kernel_page(uint32_t vaddr, uint32_t phys_addr)
{
    if (!is_valid_vaddr(vaddr)) {
        return;
    }
    
    /* Vérifier que l'adresse est dans l'espace noyau TTBR1 (>=2GB) */
    if (vaddr < 0x40000000) {
        KERROR("Address 0x%08X is in user space, use user mapping functions\n", vaddr);
        return;
    }
    
    // Utiliser TTBR1 pour l'espace noyau
    uint32_t* kernel_pgdir = get_kernel_pgdir();
    
    if (!kernel_pgdir) {
        KERROR("map_kernel_page: No valid kernel page directory\n");
        return;
    }
    
    // Pour le kernel, utiliser des sections de 1MB
    uint32_t section_index = get_L1_index(vaddr) - 0x800; // Ajuster pour TTBR1
    uint32_t section_base = phys_addr & PDE_SECTION_BASE;
    
    // Vérifier l'index TTBR1
    if (section_index >= 2048) {
        KERROR("Kernel section index out of range: %u\n", section_index);
        return;
    }
    
    // Configuration kernel avec permissions privilégiées
    uint32_t pde;
    
    if (vaddr >= DEVICE_START && vaddr < DEVICE_END) {
        // Device memory: non-cacheable, non-bufferable
        pde = section_base |
              0x00000002 |      // Section bit
              0x00000400;       // AP[1:0] = 01 (privileged access)
    } else {
        // Kernel RAM: cacheable, bufferable
        pde = section_base |
              0x00000002 |      // Section bit
              0x00000400 |      // AP[1:0] = 01 (privileged access)
              0x00000004 |      // Cacheable
              0x00000008;       // Bufferable
    }
    
    // Écrire l'entrée dans TTBR1
    kernel_pgdir[section_index] = pde;
    
    // Invalider le TLB pour cette adresse (pas d'ASID pour le noyau)
    invalidate_tlb_page(vaddr);
    
    // Barriers
    asm volatile("dsb" ::: "memory");
    asm volatile("isb" ::: "memory");
}

uint32_t get_L1_index(uint32_t vaddr){
    return vaddr >= get_split_boundary() ? KERNEL_L1_INDEX(vaddr) : vaddr >> 20 ; 
}

uint32_t get_physical_address(uint32_t* pgdir, uint32_t vaddr) {
    return get_phys_addr_from_pgdir(pgdir, vaddr);
}


void invalidate_tlb_all(void)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0));
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

static inline void invalidate_tlb_page_global(uint32_t vaddr)
{
    vaddr &= ~0xFFFu;
    asm volatile(
        "dsb ishst         \n"
        "mcr p15, 0, %0, c8, c7, 3 \n"  // TLBI MVA, ALL ASID (TLBIMVAA)
        "dsb ish          \n"
        "isb              \n"
        :: "r"(vaddr) : "memory");
}

void invalidate_tlb_page(uint32_t vaddr)
{
    //vaddr &= ~(PAGE_SIZE - 1);
    
    //KDEBUG("invalidate_tlb_page: invalidating 0x%08X\n", vaddr);
    //debug_mmu_state();

    invalidate_tlb_page_global(vaddr);
    
/*     asm volatile(
        "dsb                            \n"
        "mcr p15, 0, %0, c8, c7, 1      \n"  // TLBIMVA
        "dsb                            \n"
        "isb                            \n"
        :
        : "r"(vaddr)
        : "memory"
    ); */
    
    //KDEBUG("invalidate_tlb_page: completed\n");
}

/* Nouvelle fonction: Invalider TLB par adresse et ASID */
void invalidate_tlb_page_asid(uint32_t vaddr, uint32_t asid)
{
    vaddr &= ~(PAGE_SIZE - 1);
    uint32_t tlbimvaa_val = vaddr | (asid & ASID_MASK);
    
    //KDEBUG("invalidate_tlb_page_asid: vaddr=0x%08X, asid=%u\n", vaddr, asid);
    
    asm volatile(
        "dsb                            \n"
        "mcr p15, 0, %0, c8, c7, 3      \n"  // TLBIMVAA - invalidate by VA and ASID
        "dsb                            \n"
        "isb                            \n"
        :
        : "r"(tlbimvaa_val)
        : "memory"
    );
    
    //KDEBUG("invalidate_tlb_page_asid: completed\n");
}

/* Nouvelle fonction: Invalider TLB par ASID seulement */
void invalidate_tlb_asid(uint32_t asid)
{
    //KDEBUG("invalidate_tlb_asid: asid=%u / get_current_asid=%u\n", asid, get_current_asid());

    tlb_flush_by_asid(asid);
    
/*     asm volatile(
        "dsb                            \n"
        "nop                            \n"  // Délai après TLB invalidation
        "nop                            \n"
        "nop                            \n"  // Cortex-A15 recommande 3+ cycles
        "mcr p15, 0, %0, c8, c7, 2      \n"  // TLBIASID - invalidate by ASID
        "nop                            \n"  // Délai après TLB invalidation
        "nop                            \n"
        "nop                            \n"  // Cortex-A15 recommande 3+ cycles
        "dsb                            \n"
        "nop                            \n"  // Délai après TLB invalidation
        "nop                            \n"
        "nop                            \n"  // Cortex-A15 recommande 3+ cycles
        "isb                            \n"
        :
        : "r"(asid & ASID_MASK)
        : "memory"
    ); */
    
    //KDEBUG("invalidate_tlb_asid: completed\n");
}

uint32_t get_ttbr0(void)
{
    uint32_t ttbr0;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    return ttbr0;
}

void set_ttbr0(uint32_t ttbr0)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 0" : : "r"(ttbr0));
    __asm__ volatile("isb");
}

uint32_t* get_kernel_pgdir(void)
{
    return kernel_pgdir;
}

uint32_t* get_kernel_ttbr0(void)
{
    return ttbr0_pgdir;
}

#if(0)
uint32_t get_ttbr1(void)
{
    uint32_t ttbr1;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    return ttbr1;
}

void set_ttbr1(uint32_t ttbr1)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" : : "r"(ttbr1));
    __asm__ volatile("isb");
}

/* Implémentations des fonctions CP15 pour éviter conflits avec arm.h */
uint32_t get_ttbr1(void)
{
    uint32_t ttbr1;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    return ttbr1;
}

void set_ttbr1(uint32_t ttbr1)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" : : "r"(ttbr1));
    __asm__ volatile("isb");
}

uint32_t get_ttbcr(void)
{
    uint32_t ttbcr;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    return ttbcr;
}

void set_ttbcr(uint32_t ttbcr)
{
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 2" : : "r"(ttbcr));
    __asm__ volatile("isb");
}

uint32_t get_contextidr(void)
{
    uint32_t contextidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    return contextidr;
}

void set_contextidr(uint32_t contextidr)
{
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 1" : : "r"(contextidr));
    __asm__ volatile("isb");
}
#endif

/* Fonctions de debug mises à jour */
void debug_mmu_state(void)
{
    uint32_t ttbr0 = get_ttbr0();
    uint32_t ttbr1 = get_ttbr1();
    uint32_t ttbcr = get_ttbcr();
    uint32_t contextidr = get_contextidr() ;
    uint32_t sctlr = get_sctlr();
    uint32_t dacr = get_dacr();
    
    //__asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    //__asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    
    KDEBUG("=== MMU SPLIT TTBR STATE DEBUG ===\n");
    KDEBUG("kernel_page_dir:      %p\n", kernel_page_dir);
    KDEBUG("TTBR0 register:       0x%08X (user space)\n", ttbr0);
    KDEBUG("TTBR1 register:       0x%08X (kernel space)\n", ttbr1);
    KDEBUG("TTBCR register:       0x%08X (N=%d)\n", ttbcr, ttbcr & 0x7);
    KDEBUG("CONTEXTIDR:           0x%08X (ASID=%d)\n", contextidr, contextidr & ASID_MASK);
    KDEBUG("Current ASID:         %u\n", current_asid);
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
    
    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    
    KDEBUG("=== STACK CHECK [%s] ===\n", location);
    
    // Detecter si on est dans une pile de tache
    bool in_task_stack = false;
    if (current_task && current_task->stack_base) {
        uint32_t task_stack_bottom = (uint32_t)current_task->stack_base;
        uint32_t task_stack_top = task_stack_bottom + current_task->stack_size;
        
        if (current_sp >= task_stack_bottom && current_sp <= task_stack_top) {
            in_task_stack = true;
            
            KDEBUG("CONTEXT: Task '%s' stack\n", current_task->name);
            KDEBUG("Task stack bottom: 0x%08X\n", task_stack_bottom);
            KDEBUG("Task stack top:    0x%08X\n", task_stack_top);
            KDEBUG("Task stack size:   %u bytes (%u KB)\n", 
                   current_task->stack_size, current_task->stack_size / 1024);
            KDEBUG("Current SP:        0x%08X\n", current_sp);
            
            uint32_t used = task_stack_top - current_sp;
            uint32_t free = current_sp - task_stack_bottom;
            KDEBUG("OK SP in valid TASK range\n");
            KDEBUG("   Stack used:  %u bytes\n", used);
            KDEBUG("   Stack free:  %u bytes\n", free);
            
            if (used > (current_task->stack_size * 3/4)) {
                KWARN("WARNING  Task stack usage high: %u/%u bytes (%u%%)\n", 
                      used, current_task->stack_size, 
                      used * 100 / current_task->stack_size);
            }
        }
    }
    
    if (!in_task_stack) {
        // Verification pile kernel principale
        uint32_t stack_bottom = (uint32_t)&__stack_bottom;
        uint32_t stack_top = (uint32_t)&__stack_top;
        uint32_t stack_size = stack_top - stack_bottom;
        
        KDEBUG("CONTEXT: Kernel main stack\n");
        KDEBUG("Kernel stack bottom: 0x%08X\n", stack_bottom);
        KDEBUG("Kernel stack top:    0x%08X\n", stack_top);
        KDEBUG("Kernel stack size:   %u bytes (%u KB)\n", stack_size, stack_size / 1024);
        KDEBUG("Current SP:          0x%08X\n", current_sp);
        
        if (current_sp < stack_bottom) {
            KERROR("KO SP UNDERFLOW! SP below kernel stack bottom\n");
            KERROR("   Underflow by: %u bytes\n", stack_bottom - current_sp);
        } else if (current_sp >= stack_top) {
            KERROR("KO SP OVERFLOW! SP above kernel stack top\n"); 
            KERROR("   Overflow by: %u bytes\n", current_sp - stack_top);
        } else {
            uint32_t used = stack_top - current_sp;
            uint32_t free = current_sp - stack_bottom;
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
    
    KDEBUG("=== MEMORY LAYOUT CHECK ===\n");
    KDEBUG("Kernel start:  0x%08X\n", (uint32_t)&__start);
    KDEBUG("Kernel end:    0x%08X\n", (uint32_t)&__end);
    KDEBUG("BSS start:     0x%08X\n", (uint32_t)&__bss_start);
    KDEBUG("BSS end:       0x%08X\n", (uint32_t)&__bss_end);
    
    /* Verifier que les adresses sont coherentes */
    if ((uint32_t)&__start > (uint32_t)&__end) {
        KERROR("KO Kernel start > end!\n");
    }
    
    if ((uint32_t)&__bss_start > (uint32_t)&__bss_end) {
        KERROR("KO BSS start > end!\n");
    }
    
    //KDEBUG("MMU start:     0x%08X\n", (uint32_t)&__mmu_tables_start);
    //KDEBUG("MMU end:       0x%08X\n", (uint32_t)&__mmu_tables_end);


    /* Verifier le heap */
    extern uint8_t* heap_base;
    extern size_t heap_size;
    
    if (heap_base) {
        KDEBUG("Heap base:     0x%08X\n", (uint32_t)heap_base);
        KDEBUG("Heap size:     %u bytes\n", heap_size);
        KDEBUG("Heap end:      0x%08X\n", (uint32_t)heap_base + heap_size);
    }
}

void dump_kernel_stack(int depth)
{
    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    
    KDEBUG("=== KERNEL STACK DUMP ===\n");
    KDEBUG("SP: 0x%08X\n", current_sp);
    
    uint32_t* stack_ptr = (uint32_t*)current_sp;
    
    for (int i = 0; i < depth && i < 16; i++) {
        if ((uint32_t)(stack_ptr + i) >= 0x40000000 && 
            (uint32_t)(stack_ptr + i) < 0x50000000) {
            KDEBUG("[SP+%02d] 0x%08X: 0x%08X\n", 
                   i * 4, (uint32_t)(stack_ptr + i), stack_ptr[i]);
        } else {
            KDEBUG("[SP+%02d] INVALID ADDRESS\n", i * 4);
            break;
        }
    }
}

void setup_svc_stack(void) {
    extern uint32_t __svc_stack_top;
    
    // Vérifier que MMU est active
    uint32_t sctlr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    if (!(sctlr & 1)) {
        kprintf("ERROR: Setting up SVC stack before MMU!\n");
        return;
    }
    
    uint32_t svc_sp = (uint32_t)&__svc_stack_top & ~7;
    kprintf("Configuring SVC stack at 0x%08X\n", svc_sp);
    
    __asm__ volatile("mov sp, %0" : : "r"(svc_sp));
    kprintf("SVC stack configured successfully\n");
}
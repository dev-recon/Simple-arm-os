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

/* Pointeurs globaux */
uint32_t* kernel_pgdir = kernel_page_dir;   /* TTBR1 - Espace noyau */

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



void dump_l1( uint32_t va) {
    //uint32_t N = 2; // tu l'as déjà
    uint32_t split = 0x40000000;
    uint32_t idx = (va >= split) ? ((va >> 20) - (split >> 20)) : (va >> 20);
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

    setup_kernel_space();

    //preallocate_temp_mapping_system();  // Pendant qu'on a l'identity mapping
    //create_l2_access_zone();            // Idem

    // Écriture des TTBR
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 0" :: "r"((uint32_t)kernel_page_dir));  // TTBR0
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 1" :: "r"((uint32_t)&kernel_page_dir[1024]));  // TTBR1

    // TTBCR : N = 2 (split à 0x40000000), EAE = 0 (format court)
    uint32_t ttbcr = 0x2;
    __asm__ volatile("mcr p15, 0, %0, c2, c0, 2" :: "r"(ttbcr));

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

    uint32_t next_index = KERNEL_L1_INDEX(next_pc);
    uint32_t next_entry = kernel_page_dir[next_index];

    if ((next_entry & 0x3) != 0x2) {
        simple_kprintf("CRITICAL: Next PC not mapped as section!\n");
        while (1);
    }

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
    
    kprintf("MMU: Setting up kernel space (TTBR1) from 0x%08X...\n", split_boundary);

    kprintf("MMU: Mapping range 0x%08X - 0x%08X\n", split_boundary, ram_end);
    kprintf("MMU: Max index will be %u (limit: 3072)\n", 
        ((ram_end-1) >> 20) - (split_boundary >> 20));
    
    /* Clear kernel page directory */
    memset(kernel_page_dir, 0, sizeof(kernel_page_dir));

    // 1. Mapper TOUTE la zone basse (0-1GB) en identity mapping dans TTBR0
    for (uint32_t addr = 0; addr < 0x40000000; addr += 0x100000) {
        uint32_t index = addr >> 20;  // Index 0-1023
        kernel_page_dir[index] = addr | 0xC0E;
    }
    kprintf("Mapped low memory (TTBR0): 0x0 - 0x40000000\n");
    
    /* Map kernel/RAM space - seulement les sections >= split_boundary pour TTBR1 */
    for (uint32_t addr = split_boundary; addr < ram_end; addr += 0x100000) {

        //uint32_t index = addr >> 20;
        //uint32_t index = (addr >> 20) - (split_boundary >> 20);  // Index relatif à TTBR1
                // TTBR1 pointe sur &kernel_page_dir[1024], donc :
        // - Index 0 de TTBR1 = kernel_page_dir[1024] = adresse 0x40000000
        // - Index 1 de TTBR1 = kernel_page_dir[1025] = adresse 0x40100000
        uint32_t ttbr1_index = (addr - split_boundary) >> 20;  // 0, 1, 2...
        uint32_t array_index = 1024 + ttbr1_index;             // 1024, 1025, 1026...

        
        /* Skip la zone réservée aux mappings temporaires */
        //if (addr >= TEMP_MAPPING_START && addr < TEMP_MAPPING_END) {
        //    continue;
        //}
        
        kernel_page_dir[array_index] = addr |           
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */

        mapped_sections++;
    }
    
    kprintf("MMU: Kernel RAM sections mapped: %u\n", mapped_sections);

    kprintf("MMU: Kernel RAM sections mapped before temp area: %u\n", mapped_sections);

    /* 3. NOUVEAU: Pré-allouer et configurer les temp mappings ICI */
    kprintf("MMU: Setting up temporary mapping slots...\n");
    setup_temp_mapping_slots();
    
    /* 4. Map le reste de l'espace kernel après la zone temp */
    for (uint32_t addr = TEMP_MAPPING_END; addr < ram_end; addr += 0x100000) {
        uint32_t ttbr1_index = (addr - split_boundary) >> 20;
        uint32_t array_index = 1024 + ttbr1_index;
        
        kernel_page_dir[array_index] = addr |           
                        0x00000002 |      /* Section bit */
                        0x00000C00 |      /* AP[11:10] = 11 (Kernel RW) */
                        0x00000004 |      /* C - Cacheable */
                        0x00000008;       /* B - Bufferable */
        mapped_sections++;
    }
    
    /* Map device space */
    for (uint32_t addr = DEVICE_START; addr < DEVICE_END; addr += 0x100000) {
        if (addr >= split_boundary) {
            uint32_t ttbr1_index = (addr - split_boundary) >> 20;
            uint32_t array_index = 1024 + ttbr1_index;
            
            // Devices: non-cacheable, non-bufferable
            kernel_page_dir[array_index] = addr | 
                        0x00000002 |      /* Section */
                        0x00000C00;       /* AP = 11 (RW), pas de cache/buffer */
            mapped_sections++;
        }
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
    
    asid_map[1] = true;

    asid_map[255] = true;
    return 1;
}

static void free_asid(uint32_t asid)
{
    if (asid > 0 && asid < MAX_ASID) {
        asid_map[asid] = false;
        
        /* Invalider les entrées TLB pour cet ASID */
        __asm__ volatile("mcr p15, 0, %0, c8, c7, 2" : : "r"(asid));  /* TLBIASID */
    }
}

void set_current_asid(uint32_t asid)
{
    uint32_t contextidr;
    
    KDEBUG("Setting up ASID %d\n", asid);
    /* Lire le CONTEXTIDR actuel */
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));

    KDEBUG("Current contextidr = 0x%08X\n", contextidr);
    
    /* Mettre à jour seulement les bits ASID (bits 7:0) */
    contextidr = (contextidr & ~CONTEXTIDR_ASID_MASK) | (asid & CONTEXTIDR_ASID_MASK);
    KDEBUG("Setting up contextidr = 0x%08X\n", contextidr);
   
    /* Ecrire le nouveau CONTEXTIDR */
    __asm__ volatile("mcr p15, 0, %0, c13, c0, 1" : : "r"(contextidr));
    __asm__ volatile("isb");
    
    KDEBUG("Setting up ASID %d SUCCESSFUL\n", asid);

    current_asid = asid;
}

uint32_t get_current_asid(void)
{
    uint32_t contextidr;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    return contextidr & CONTEXTIDR_ASID_MASK;
}

/* Fonctions publiques modifiées pour ASID */

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
    
    uint32_t pgdir_phys = (uint32_t)pgdir;
    uint32_t aligned_pgdir = pgdir_phys & ~0x3FFF;
    
    /* SÉQUENCE SÉCURISÉE DE CHANGEMENT TTBR0 seulement */
    /* TTBR1 reste inchangé car il contient l'espace noyau */
    
    kprintf("MMU: Switching user address space (TTBR0 only) pgdir_phys = 0x%08X, aligned_pgdir = 0x%08X\n", pgdir_phys, aligned_pgdir);
    
    /* Changer seulement TTBR0 */
    asm volatile(
        "mcr p15, 0, %0, c2, c0, 0  \n"  /* Write TTBR0 */
        "isb                        \n"  /* Immediate barrier */
        :
        : "r"(aligned_pgdir)
        : "memory"
    );
    
    /* Vérification */
    uint32_t new_ttbr0;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(new_ttbr0));
    
    if (new_ttbr0 == aligned_pgdir) {
        KDEBUG("TTBR0 switch SUCCESS: 0x%08X\n", new_ttbr0);
    } else {
        KERROR("TTBR0 switch FAILED: expected=0x%08X, got=0x%08X\n",
               aligned_pgdir, new_ttbr0);
    }
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
    
        /* Switch ASID */
    set_current_asid(asid);
    instruction_sync_barrier();

    /* Switch TTBR0 */
    switch_address_space(pgdir);
    instruction_sync_barrier();
    
    KDEBUG("Address space switched: pgdir=0x%08X, ASID=%u\n", (uint32_t)pgdir, asid);
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
        
        uint32_t index = addr >> 20;
        
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

int map_user_page(uint32_t* pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags)
{
    KDEBUG("map_user_page: vaddr=0x%08X, paddr=0x%08X, flags=0x%08X\n", 
           vaddr, phys_addr, vma_flags);
    
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

    KDEBUG("map_user_page: pgdir=0x%08X, vaddr=0x%08X, paddr=0x%08X, flags=0x%08X\n", 
           pgdir, vaddr, phys_addr, vma_flags);
    
    KDEBUG("VMA flags: R%s W%s X%s\n",
           (vma_flags & VMA_READ) ? "+" : "-",
           (vma_flags & VMA_WRITE) ? "+" : "-",
           (vma_flags & VMA_EXEC) ? "+" : "-");
    
    // Utiliser des pages de 4KB
    uint32_t l1_index = vaddr >> 20;        // Bits 31-20
    uint32_t l2_index = (vaddr >> 12) & 0xFF; // Bits 19-12
    
    KDEBUG("L1 index: %u, L2 index: %u\n", l1_index, l2_index);
    
    // Vérifier/créer la table L2
    uint32_t* l1_entry = &pgdir[l1_index];
    uint32_t* l2_table;
    
    if (!(*l1_entry & 0x1)) {
        // Allouer une nouvelle table L2
        void* l2_page = allocate_physical_page();
        if (!l2_page) {
            KERROR("Failed to allocate L2 table\n");
            return -1;
        }
        KDEBUG("L2 creation: Allocate Physical Page OK\n");
        
        uint32_t l2_phys = (uint32_t)l2_page;
        
        // Mapper temporairement pour initialiser
        uint32_t l2_temp = map_temp_page(l2_phys);
        //uint32_t l2_temp = map_temp_page_large(l2_phys, 12*1024);
        if (l2_temp == 0) {
            KERROR("Failed to map L2 table temporarily\n");
            free_physical_page(l2_page);
            return -1;
        }

        KDEBUG("L2 creation: Map Temp Page OK l2_temp 0x%08X\n", l2_temp);
        
        // Zéroiser la table L2
        memset((void*)l2_temp, 0, PAGE_SIZE);
        unmap_temp_page((void*)l2_temp);
        
        // Configurer l'entrée L1 style Cortex-A15
        *l1_entry = (l2_phys & 0xFFFFFC00) | 0x01;  // Coarse page table
        
        KDEBUG("Created L2 table at phys 0x%08X\n", l2_phys);
    }

    //KDEBUG("L1 test: !(*l1_entry & 0x1) failed\n");
    
    // Obtenir l'adresse de la table L2
    uint32_t l2_phys = *l1_entry & 0xFFFFFC00;
    uint32_t l2_temp = map_temp_page(l2_phys);
    //uint32_t l2_temp = map_temp_page_large(l2_phys, 12*1024);
    if (l2_temp == 0) {
        KERROR("Failed to map existing L2 table\n");
        return -1;
    }
    
    l2_table = (uint32_t*)l2_temp;
    
    // Déterminer les permissions ARM
    uint32_t page_flags = 0x02;  // Small page type
    
    // Permissions d'accès
    if (vma_flags & VMA_WRITE) {
        page_flags |= 0x30;  // AP[1:0] = 11 (user R/W)
    } else {
        page_flags |= 0x20;  // AP[1:0] = 10 (user R/O) 
    }
    
    // Execute Never bit
    if (!(vma_flags & VMA_EXEC)) {
        page_flags |= 0x01;  // XN bit
    }
    
    // Cache/Buffer pour RAM
    if (vaddr >= VIRT_RAM_START && vaddr < VIRT_RAM_END) {
        page_flags |= 0x0C;  // Cacheable + Bufferable
    }
    
    KDEBUG("ARM page flags: 0x%08X\n", page_flags);
    
    // Configurer l'entrée L2
    l2_table[l2_index] = (phys_addr & 0xFFFFF000) | page_flags;
    
    KDEBUG("L2[%u] = 0x%08X\n", l2_index, l2_table[l2_index]);
    
    // Unmap la table L2
    unmap_temp_page((void*)l2_temp);
    
    // Invalider le TLB pour cette adresse avec ASID
    invalidate_tlb_page_asid(vaddr, get_current_asid());
    data_sync_barrier();
    instruction_sync_barrier();
    
    KINFO("Successfully mapped page 0x%08X -> 0x%08X\n", vaddr, phys_addr);
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
    uint32_t section_index = (vaddr >> 20) - 0x800; // Ajuster pour TTBR1
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

uint32_t get_physical_address(uint32_t* pgdir, uint32_t vaddr) {
    uint32_t l1_index = vaddr >> 20;
    uint32_t l1_entry = pgdir[l1_index];

    KDEBUG("[get_physical_address] : Getting physical for VA = 0x%08X (L1 index = %u)\n", vaddr, l1_index);
    KDEBUG("[get_physical_address] : L1 entry = 0x%08X\n", l1_entry);

    uint32_t type = l1_entry & 0x3;

    if (type == 0) {
        KDEBUG("[get_physical_address] : Fault entry\n");
        return 0;
    } else if (type == 2) {
        // Section mapping (1MB)
        uint32_t section_base = l1_entry & 0xFFF00000;
        uint32_t offset = vaddr & 0x000FFFFF;
        uint32_t phys = section_base + offset;
        KDEBUG("[get_physical_address] : Section -> PA = 0x%08X\n", phys);
        return phys;
    } else if (type == 1) {
        // Coarse page table
        uint32_t l2_index = (vaddr >> 12) & 0xFF;
        uint32_t l2_table_phys = l1_entry & 0xFFFFFC00;
        uint32_t l2_mapped_virt = map_temp_page(l2_table_phys);
        uint32_t* l2_table = (uint32_t*)l2_mapped_virt;
        uint32_t l2_entry = l2_table[l2_index];
        unmap_temp_page((void*)l2_mapped_virt);

        uint32_t l2_type = l2_entry & 0x3;
        if (l2_type != 2) {
            KDEBUG("[get_physical_address] : Invalid small page type (0x%X)\n", l2_type);
            return 0;
        }

        uint32_t small_page_base = l2_entry & 0xFFFFF000;
        uint32_t offset = vaddr & 0xFFF;
        uint32_t phys = small_page_base + offset;
        KDEBUG("[get_physical_address] : Small page -> PA = 0x%08X\n", phys);
        return phys;
    } else {
        KDEBUG("[get_physical_address] : Unsupported L1 entry type: %u\n", type);
        return 0;
    }
}


uint32_t get_physical_address2(uint32_t* pgdir, uint32_t vaddr) {
    uint32_t l1_index = vaddr >> 20;
    uint32_t l2_index = (vaddr >> 12) & 0xFF;
    
    KDEBUG("[get_physical_address] : getting physical for address = 0x%08X in pgdir 0x%08X\n", vaddr, (uint32_t)pgdir);
    KDEBUG("[get_physical_address] : L1 index = %d, L2 index = %d\n", l1_index, l2_index);
    
    uint32_t l1_entry = pgdir[l1_index];
    KDEBUG("[get_physical_address] : L1[%d] = 0x%08X\n", l1_index, l1_entry);
    
    uint32_t pde_type = l1_entry & 0x3;
    KDEBUG("[get_physical_address] : PDE_TYPE = %d\n", pde_type);
    
    if (pde_type != 1) {  // Pas une coarse page table
        KDEBUG("[get_physical_address] : Not a coarse page table, returning 0\n");
        return 0;
    }
    
    // Obtenir la table L2 physique
    uint32_t l2_table_phys = l1_entry & 0xFFFFFC00;
    KDEBUG("[get_physical_address] : L2 table phys = 0x%08X\n", l2_table_phys);
    
    // Mapper temporairement la table L2
    uint32_t l2_mapped_virt = map_temp_page(l2_table_phys);
    uint32_t* l2_table = (uint32_t*)l2_mapped_virt;
    
    uint32_t l2_entry = l2_table[l2_index];
    KDEBUG("[get_physical_address] : L2[%d] = 0x%08X\n", l2_index, l2_entry);

    uint32_t pte_type = l2_entry & 0x3;
    KDEBUG("[get_physical_address] : PTE_TYPE = %d\n", pte_type);
    
    if (pte_type != 2) {  // Small page ARM = type 2
        KDEBUG("[get_physical_address] : Not a small page (type=%d)\n", pte_type);
        unmap_temp_page((void*)l2_mapped_virt);
        return 0;
    }
    
    unmap_temp_page((void*)l2_mapped_virt);
    
    uint32_t phys_base = l2_entry & 0xFFFFF000;
    uint32_t offset = vaddr & 0xFFF;
    uint32_t result = phys_base + offset;
    
    KDEBUG("[get_physical_address] : Final result = 0x%08X\n", result);
    return result;
}

void invalidate_tlb_all(void)
{
    __asm__ volatile("mcr p15, 0, %0, c8, c7, 0" : : "r"(0));
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

void invalidate_tlb_page(uint32_t vaddr)
{
    vaddr &= ~(PAGE_SIZE - 1);
    
    //KDEBUG("invalidate_tlb_page: invalidating 0x%08X\n", vaddr);
    
    asm volatile(
        "dsb                            \n"
        "mcr p15, 0, %0, c8, c7, 1      \n"  // TLBIMVA
        "dsb                            \n"
        "isb                            \n"
        :
        : "r"(vaddr)
        : "memory"
    );
    
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
    //KDEBUG("invalidate_tlb_asid: asid=%u\n", asid);
    
    asm volatile(
        "dsb                            \n"
        "mcr p15, 0, %0, c8, c7, 2      \n"  // TLBIASID - invalidate by ASID
        "dsb                            \n"
        "isb                            \n"
        :
        : "r"(asid & ASID_MASK)
        : "memory"
    );
    
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
    uint32_t ttbcr, contextidr;
    
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    
    KDEBUG("=== MMU SPLIT TTBR STATE DEBUG ===\n");
    KDEBUG("kernel_page_dir:      %p\n", kernel_page_dir);
    KDEBUG("TTBR0 register:       0x%08X (user space)\n", ttbr0);
    KDEBUG("TTBR1 register:       0x%08X (kernel space)\n", ttbr1);
    KDEBUG("TTBCR register:       0x%08X (N=%d)\n", ttbcr, ttbcr & 0x7);
    KDEBUG("CONTEXTIDR:           0x%08X (ASID=%d)\n", contextidr, contextidr & ASID_MASK);
    KDEBUG("Current ASID:         %u\n", current_asid);
    
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
    
    uint32_t split_size = 4096 >> (ttbcr & 0x7);  // En MB
    KDEBUG("Memory split: 0--%uMB (TTBR0), %uMB--4GB (TTBR1)\n", 
           split_size * 1024, split_size * 1024);
    
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
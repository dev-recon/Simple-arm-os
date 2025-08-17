/*
 * kernel/memory/helpers.c
 * Memory Helper Functions for ARM v7 Kernel avec support split TTBR et ASID
 * 
 * Provides temporary page mapping and BSS initialization utilities
 * Compatible GNU89 standard
 */

#include <kernel/memory.h>
#include <kernel/types.h>
#include <asm/mmu.h>
#include <asm/arm.h>
#include <kernel/kernel.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#include <kernel/spinlock.h>
#include <kernel/stdarg.h>

/* External symbols from linker script */
extern uint32_t __bss_start;
extern uint32_t __bss_end;


/* Static variables for temporary mapping state */
static struct {
    uint32_t phys_addr;     /* Currently mapped physical address */
    bool in_use;            /* Is temp mapping active */
    kernel_context_save_t saved_asid;    /* ASID sauvegardé pendant le mapping temporaire */
    spinlock_t lock;        /* Protection for concurrent access */
} temp_map_state = {0, false, {0}, {0}};

/* Forward declarations of static functions */
static void init_temp_mapping_state(void);
static uint32_t* get_current_pgdir(void);
static uint32_t* get_temp_page_table(void);
static void setup_temp_page_table_entry(uint32_t* pt, uint32_t phys_addr);
static void clear_temp_page_table_entry(uint32_t* pt);
static bool is_temp_mapping_initialized(void);
static uint32_t* get_temp_page_table_for_slot(int slot);
static bool validate_temp_slot_configuration(int slot);
static void init_multi_temp_mapping_state(void);
uint32_t map_temp_page_multi(uint32_t phys_addr, int num_pages);


#define TEMP_USER_MAP_VADDR     0x80001000  // juste après TEMP_MAP_VADDR
#define TEMP_USER_L1_INDEX      KERNEL_L1_INDEX(TEMP_USER_MAP_VADDR)
#define TEMP_USER_L2_INDEX      ((TEMP_USER_MAP_VADDR >> 12) & 0xFF)
#define TEMP_MAP_BASE_VADDR     TEMP_MAP_VADDR  /* Base address for temp mappings */
#define TEMP_MAP_L1_SPACING     0x00100000  /* 20 KB spacing = different L1 entries */
#define L2_CONTROL_VADDR        0x7F000000  /* Dans l'espace kernel */




// Définitions des bits pour les entrées de table de pages ARM
#define L1_TYPE_MASK        0x3
#define L1_TYPE_FAULT       0x0
#define L1_TYPE_COARSE      0x1
#define L1_TYPE_SECTION     0x2
#define L1_TYPE_FINE        0x3

// Bits pour les sections (1MB)
#define L1_SECT_AP_MASK     0xC00
#define L1_SECT_AP_SHIFT    10
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_nG          (1 << 17)    // not Global
#define L1_SECT_S           (1 << 16)    // Shareable
#define L1_SECT_C           (1 << 3)     // Cacheable
#define L1_SECT_B           (1 << 2)     // Bufferable
#define L1_SECT_XN          (1 << 4)     // eXecute Never

// Bits pour les tables L2 (L1 coarse entries)
#define L1_COARSE_DOMAIN_MASK   0x1E0
#define L1_COARSE_DOMAIN_SHIFT  5
#define L1_COARSE_NS        (1 << 3)     // Non-Secure
#define L1_COARSE_PXN       (1 << 2)     // Privileged eXecute Never

// Bits pour les pages L2 (4KB)
#define L2_TYPE_MASK        0x3
#define L2_TYPE_FAULT       0x0
#define L2_TYPE_LARGE       0x1          // 64KB
#define L2_TYPE_SMALL       0x2          // 4KB
#define L2_TYPE_TINY        0x3          // 1KB (deprecated)

#define L2_SMALL_AP_MASK    0x230
#define L2_SMALL_AP0        (1 << 4)
#define L2_SMALL_AP1        (1 << 5)
#define L2_SMALL_APX        (1 << 9)
#define L2_SMALL_nG         (1 << 11)    // not Global
#define L2_SMALL_S          (1 << 10)    // Shareable
#define L2_SMALL_C          (1 << 3)     // Cacheable
#define L2_SMALL_B          (1 << 2)     // Bufferable
#define L2_SMALL_XN         (1 << 0)     // eXecute Never

// Valeurs AP (Access Permissions)
#define AP_NO_ACCESS        0x0
#define AP_PRIV_RW          0x1
#define AP_USER_RO          0x2
#define AP_ALL_RW           0x3

static const char* get_ap_description(uint32_t ap, uint32_t apx) {
    uint32_t combined = (apx << 2) | ap;
    switch (combined) {
        case 0x0: return "No access";
        case 0x1: return "Priv RW";
        case 0x2: return "User RO, Priv RW";
        case 0x3: return "User RW, Priv RW";
        case 0x4: return "RESERVED";
        case 0x5: return "Priv RO";
        case 0x6: return "User RO, Priv RO";
        case 0x7: return "User RO, Priv RO (deprecated)";
        default: return "Unknown";
    }
}

static const char* get_l1_type_description(uint32_t type) {
    switch (type) {
        case L1_TYPE_FAULT: return "Fault";
        case L1_TYPE_COARSE: return "Coarse (L2 table)";
        case L1_TYPE_SECTION: return "Section (1MB)";
        case L1_TYPE_FINE: return "Fine (deprecated)";
        default: return "Unknown";
    }
}

static const char* get_l2_type_description(uint32_t type) {
    switch (type) {
        case L2_TYPE_FAULT: return "Fault";
        case L2_TYPE_LARGE: return "Large (64KB)";
        case L2_TYPE_SMALL: return "Small (4KB)";
        case L2_TYPE_TINY: return "Tiny (1KB, deprecated)";
        default: return "Unknown";
    }
}

void analyze_l1_entry(uint32_t entry, uint32_t index) {
    uint32_t type = entry & L1_TYPE_MASK;
    
    KDEBUG("[L1-%04d] Entry: 0x%08X, Type: %s\n", 
           index, entry, get_l1_type_description(type));
    
    if (type == L1_TYPE_FAULT) {
        KDEBUG("          -> Page fault will occur\n");
        return;
    }
    
    if (type == L1_TYPE_SECTION) {
        uint32_t ap = (entry & L1_SECT_AP_MASK) >> L1_SECT_AP_SHIFT;
        uint32_t apx = (entry & L1_SECT_APX) ? 1 : 0;
        uint32_t phys = entry & 0xFFF00000;
        
        KDEBUG("          -> Section: Phys=0x%08X\n", phys);
        KDEBUG("          -> AP: %s\n", get_ap_description(ap, apx));
        KDEBUG("          -> nG=%d, S=%d, XN=%d, C=%d, B=%d\n",
               !!(entry & L1_SECT_nG),
               !!(entry & L1_SECT_S),
               !!(entry & L1_SECT_XN),
               !!(entry & L1_SECT_C),
               !!(entry & L1_SECT_B));
    } else if (type == L1_TYPE_COARSE) {
        uint32_t domain = (entry & L1_COARSE_DOMAIN_MASK) >> L1_COARSE_DOMAIN_SHIFT;
        uint32_t l2_phys = entry & 0xFFFFFC00;
        
        KDEBUG("          -> L2 Table: Phys=0x%08X\n", l2_phys);
        KDEBUG("          -> Domain=%d, NS=%d, PXN=%d\n",
               domain,
               !!(entry & L1_COARSE_NS),
               !!(entry & L1_COARSE_PXN));
    }
}

void analyze_l2_entry(uint32_t entry, uint32_t index, uint32_t l1_index) {
    uint32_t type = entry & L2_TYPE_MASK;
    
    KDEBUG("[L2-%04d.%03d] Entry: 0x%08X, Type: %s\n", 
           l1_index, index, entry, get_l2_type_description(type));
    
    if (type == L2_TYPE_FAULT) {
        KDEBUG("               -> Page fault will occur\n");
        return;
    }
    
    if (type == L2_TYPE_SMALL) {
        uint32_t ap = 0;
        if (entry & L2_SMALL_AP0) ap |= 1;
        if (entry & L2_SMALL_AP1) ap |= 2;
        uint32_t apx = (entry & L2_SMALL_APX) ? 1 : 0;
        uint32_t phys = entry & 0xFFFFF000;
        
        KDEBUG("               -> Small page: Phys=0x%08X\n", phys);
        KDEBUG("               -> AP: %s\n", get_ap_description(ap, apx));
        KDEBUG("               -> nG=%d, S=%d, XN=%d, C=%d, B=%d\n",
               !!(entry & L2_SMALL_nG),
               !!(entry & L2_SMALL_S),
               !!(entry & L2_SMALL_XN),
               !!(entry & L2_SMALL_C),
               !!(entry & L2_SMALL_B));
    } else if (type == L2_TYPE_LARGE) {
        // Analyse pour les pages 64KB
        uint32_t phys = entry & 0xFFFF0000;
        KDEBUG("               -> Large page: Phys=0x%08X\n", phys);
    }
}

void dump_mmu_control_registers(void) {
    uint32_t ttbr0, ttbr1, ttbcr, dacr, contextidr, sctlr;
    
    // Lecture des registres MMU
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r" (ttbr0));  // TTBR0
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r" (ttbr1));  // TTBR1
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r" (ttbcr));  // TTBCR
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));   // DACR
    asm volatile("mrc p15, 0, %0, c13, c0, 1" : "=r" (contextidr)); // CONTEXTIDR
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r" (sctlr));  // SCTLR
    
    KDEBUG("=== MMU CONTROL REGISTERS ===\n");
    KDEBUG("TTBR0:      0x%08X (User space table base)\n", ttbr0);
    KDEBUG("TTBR1:      0x%08X (Kernel space table base)\n", ttbr1);
    KDEBUG("TTBCR:      0x%08X (N=%d, PD0=%d, PD1=%d)\n", 
           ttbcr, ttbcr & 0x7, !!(ttbcr & (1<<4)), !!(ttbcr & (1<<5)));
    KDEBUG("DACR:       0x%08X (Domain access control)\n", dacr);
    KDEBUG("CONTEXTIDR: 0x%08X (ASID=%d)\n", contextidr, contextidr & 0xFF);
    KDEBUG("SCTLR:      0x%08X (MMU=%d, Cache=%d, Align=%d)\n", 
           sctlr, !!(sctlr & 1), !!(sctlr & (1<<2)), !!(sctlr & (1<<1)));
    
    // Analyse des domaines
    KDEBUG("\n=== DOMAIN ACCESS CONTROL ===\n");
    for (int i = 0; i < 16; i++) {
        uint32_t domain_bits = (dacr >> (i * 2)) & 0x3;
        const char* domain_type;
        switch (domain_bits) {
            case 0: domain_type = "No access"; break;
            case 1: domain_type = "Client"; break;
            case 2: domain_type = "RESERVED"; break;
            case 3: domain_type = "Manager"; break;
            default: domain_type = "Unknown"; break;
        }
        if (domain_bits != 0) {
            KDEBUG("Domain %2d: %s (%d)\n", i, domain_type, domain_bits);
        }
    }
}

void analyze_virtual_address(uint32_t vaddr) {
    uint32_t ttbr0, ttbr1, ttbcr;
    uint32_t l1_index, l2_index;
    uint32_t *l1_table, *l2_table;
    uint32_t l1_entry, l2_entry;
    bool use_ttbr1;
    
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r" (ttbr0));
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r" (ttbr1));
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r" (ttbcr));
    
    uint32_t n = ttbcr & 0x7;
    uint32_t split_addr = 0x100000000ULL >> n;
    use_ttbr1 = (vaddr >= split_addr);
    

    l1_index = get_L1_index(vaddr);

    l2_index = L2_INDEX(vaddr);
    
    KDEBUG("=== ANALYSIS OF VIRTUAL ADDRESS 0x%08X ===\n", vaddr);
    KDEBUG("Split address: 0x%08X (N=%d)\n", (uint32_t)split_addr, n);
    KDEBUG("Using: %s (0x%08X)\n", use_ttbr1 ? "TTBR1" : "TTBR0", 
           use_ttbr1 ? ttbr1 : ttbr0);
    KDEBUG("L1 index: %d (0x%03X) [corrected for TTBR1]\n", l1_index, l1_index);
    KDEBUG("L2 index: %d (0x%02X)\n", l2_index, l2_index);
    
    // Accéder à la table L1 avec votre système de mapping temporaire
    uint32_t l1_base = (use_ttbr1 ? ttbr1 : ttbr0) & 0xFFFFC000;
    uint32_t l1_virt = map_temp_page(l1_base);
    
    if (!l1_virt) {
        KDEBUG("ERROR: Failed to map L1 table at phys 0x%08X\n", l1_base);
        return;
    }
    
    l1_table = (uint32_t *)l1_virt;
    l1_entry = l1_table[l1_index];
    
    KDEBUG("L1 table: phys=0x%08X, virt=0x%08X\n", l1_base, l1_virt);
    
    analyze_l1_entry(l1_entry, l1_index);
    
    // Si c'est une table L2, l'analyser aussi
    if ((l1_entry & L1_TYPE_MASK) == L1_TYPE_COARSE) {
        uint32_t l2_base = l1_entry & 0xFFFFFC00;
        uint32_t l2_virt = map_temp_page(l2_base);
        
        if (!l2_virt) {
            KDEBUG("ERROR: Failed to map L2 table at phys 0x%08X\n", l2_base);
        } else {
            l2_table = (uint32_t *)l2_virt;
            l2_entry = l2_table[l2_index];
            KDEBUG("L2 table: phys=0x%08X, virt=0x%08X\n", l2_base, l2_virt);
            
            analyze_l2_entry(l2_entry, l2_index, l1_index);
            
            // Nettoyer le mapping temporaire L2
            unmap_temp_page((void *)l2_virt);
        }
    }
    
    // Nettoyer le mapping temporaire L1
    unmap_temp_page((void *)l1_virt);
}

void full_mmu_diagnostic(uint32_t test_vaddr) {
    KDEBUG("=== COMPLETE MMU DIAGNOSTIC ===\n");
    
    // 1. Registres de contrôle
    dump_mmu_control_registers();
    
    // 2. Analyse de l'adresse spécifique
    analyze_virtual_address(test_vaddr);
    
    // 3. Quelques adresses clés à analyser
    KDEBUG("\n=== KEY ADDRESSES ANALYSIS ===\n");
    analyze_virtual_address(0x00000000);  // User space start
    analyze_virtual_address(0x7FFFFFFF);  // User space end
    analyze_virtual_address(0x80000000);  // Your temp mapping
    analyze_virtual_address(0xC0000000);  // Kernel space
    
    KDEBUG("=== END OF MMU DIAGNOSTIC ===\n");
}

// Fonction à appeler depuis votre code
void debug_mmu_before_crash(uint32_t test_vaddr) {
    full_mmu_diagnostic(test_vaddr);
}

// Test spécifique pour votre crash à 0x80000000
void debug_crash_address(void) {
    uint32_t crash_addr = 0x80000000;
    uint32_t ttbr0, ttbr1, ttbcr, dacr;
    
    KDEBUG("=== DIAGNOSTIC FOR CRASH ADDRESS 0x%08X ===\n", crash_addr);
    
    // Lecture des registres
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r" (ttbr0));
    asm volatile("mrc p15, 0, %0, c2, c0, 1" : "=r" (ttbr1));
    asm volatile("mrc p15, 0, %0, c2, c0, 2" : "=r" (ttbcr));
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r" (dacr));
    
    // Calculs d'index
    uint32_t l1_index = get_L1_index(crash_addr);  // = 2048 pour 0x80000000
    uint32_t l2_index = L2_INDEX(crash_addr);  // = 0
    
    // Déterminer quelle table utiliser
    uint32_t n = ttbcr & 0x7;
    bool use_ttbr1 = (crash_addr >= (0x100000000ULL >> n));
    uint32_t ttbr = use_ttbr1 ? ttbr1 : ttbr0;
    
    KDEBUG("TTBCR.N = %d, using %s (0x%08X)\n", n, 
           use_ttbr1 ? "TTBR1" : "TTBR0", ttbr);
    KDEBUG("L1 index: %d (0x%03X)\n", l1_index, l1_index);
    KDEBUG("L2 index: %d (0x%02X)\n", l2_index, l2_index);
    
    // Mapper et analyser L1
    uint32_t l1_base = ttbr & 0xFFFFC000;
    uint32_t l1_virt = map_temp_page(l1_base);
    
    if (!l1_virt) {
        KDEBUG("CRITICAL: Cannot map L1 table at 0x%08X!\n", l1_base);
        return;
    }
    
    volatile uint32_t *l1_table = (volatile uint32_t *)l1_virt;
    uint32_t l1_entry = l1_table[l1_index];
    
    KDEBUG("L1[%d] = 0x%08X\n", l1_index, l1_entry);
    
    // Analyser l'entrée L1
    uint32_t l1_type = l1_entry & 0x3;
    if (l1_type == 0) {
        KDEBUG("PROBLEM: L1 entry is FAULT! This will cause a page fault.\n");
        unmap_temp_page((void *)l1_virt);
        return;
    }
    
    if (l1_type == 1) {  // Coarse table (L2)
        uint32_t l2_base = l1_entry & 0xFFFFFC00;
        uint32_t domain = (l1_entry >> 5) & 0xF;
        
        KDEBUG("L1 points to L2 table at 0x%08X, domain %d\n", l2_base, domain);
        
        // Vérifier le domaine
        uint32_t domain_access = (dacr >> (domain * 2)) & 0x3;
        KDEBUG("Domain %d access: %s (%d)\n", domain,
               domain_access == 0 ? "NO ACCESS" :
               domain_access == 1 ? "CLIENT" :
               domain_access == 3 ? "MANAGER" : "RESERVED",
               domain_access);
        
        if (domain_access == 0) {
            KDEBUG("PROBLEM: Domain has NO ACCESS! This will cause a fault.\n");
            unmap_temp_page((void *)l1_virt);
            return;
        }
        
        // Analyser L2
        uint32_t l2_virt = map_temp_page(l2_base);
        if (!l2_virt) {
            KDEBUG("CRITICAL: Cannot map L2 table at 0x%08X!\n", l2_base);
            unmap_temp_page((void *)l1_virt);
            return;
        }
        
        volatile uint32_t *l2_table = (volatile uint32_t *)l2_virt;
        uint32_t l2_entry = l2_table[l2_index];
        
        KDEBUG("L2[%d] = 0x%08X\n", l2_index, l2_entry);
        
        // Analyser l'entrée L2
        uint32_t l2_type = l2_entry & 0x3;
        if (l2_type == 0) {
            KDEBUG("PROBLEM: L2 entry is FAULT! This will cause a page fault.\n");
        } else if (l2_type == 2) {  // Small page
            uint32_t phys_page = l2_entry & 0xFFFFF000;
            uint32_t ap = 0;
            if (l2_entry & (1 << 4)) ap |= 1;  // AP[0]
            if (l2_entry & (1 << 5)) ap |= 2;  // AP[1]
            uint32_t apx = (l2_entry & (1 << 9)) ? 1 : 0;
            
            KDEBUG("L2 maps to phys 0x%08X\n", phys_page);
            KDEBUG("AP bits: AP[1:0]=%d, APX=%d\n", ap, apx);
            
            // Décoder les permissions
            uint32_t perm = (apx << 2) | ap;
            switch (perm) {
                case 0: KDEBUG("PROBLEM: NO ACCESS permissions!\n"); break;
                case 1: KDEBUG("Permissions: Privileged RW only\n"); break;
                case 2: KDEBUG("Permissions: User RO, Privileged RW\n"); break;
                case 3: KDEBUG("Permissions: User RW, Privileged RW\n"); break;
                case 5: KDEBUG("Permissions: Privileged RO only\n"); break;
                case 6: KDEBUG("Permissions: All RO\n"); break;
                default: KDEBUG("PROBLEM: Invalid permission bits!\n"); break;
            }
            
            // Autres bits importants
            KDEBUG("Other bits: nG=%d, XN=%d, C=%d, B=%d\n",
                   !!(l2_entry & (1 << 11)),  // nG
                   !!(l2_entry & (1 << 0)),   // XN
                   !!(l2_entry & (1 << 3)),   // C
                   !!(l2_entry & (1 << 2)));  // B
        }
        
        unmap_temp_page((void *)l2_virt);
    }
    
    unmap_temp_page((void *)l1_virt);
    KDEBUG("=== END CRASH ADDRESS DIAGNOSTIC ===\n");
}


//static uint32_t temp_user_phys = 0;
//static uint32_t saved_user_asid = 0;
//static bool temp_user_in_use = false;

/* Structure pour gérer plusieurs mappings temporaires */
typedef struct {
    uint32_t virt_addr;      /* Virtual address of this slot */
    uint32_t phys_addr;      /* Physical address currently mapped */
    bool in_use;             /* Is this slot currently used */
} temp_mapping_slot_t;

/* Structure pour tables L2 pré-allouées */
static struct {
    uint32_t phys_addr;      /* Adresse physique de la table L2 */
    bool initialized;        /* Table initialisée et prête */
} preallocated_l2_tables[MAX_TEMP_MAPPINGS];

/* État global des mappings temporaires (simplifié) */
static struct {
    temp_mapping_slot_t slots[MAX_TEMP_MAPPINGS];
    spinlock_t lock;
    bool initialized;
    kernel_context_save_t saved_asid;    /* ASID sauvegardé lors du switch vers kernel */
    uint32_t* zero_page_phys; /* Page zéro pour initialisation */
} multi_temp_state;


/* Zone de contrôle pour accéder aux tables L2 */
uint32_t* l2_table_addresses[MAX_TEMP_MAPPINGS];  /* Adresses virtuelles des tables L2 */

/**
 * get_zero_page_phys - Obtenir une page physique remplie de zéros
 * Cette page doit être allouée et initialisée pendant le boot
 */
static uint32_t* get_zero_page_phys(void)
{
    if (!multi_temp_state.zero_page_phys) {
        /* Allouer une page pour les zéros */
        multi_temp_state.zero_page_phys = (uint32_t*)allocate_physical_page();
        if (multi_temp_state.zero_page_phys) {
            /* L'initialiser à zéro (pendant le boot avec identity mapping) */
            memset(multi_temp_state.zero_page_phys, 0, PAGE_SIZE);
            KDEBUG("Allocated zero page at phys 0x%08X\n", 
                   (uint32_t)multi_temp_state.zero_page_phys);
        }
    }
    return multi_temp_state.zero_page_phys;
}

/**
 * setup_l2_access_zone - Créer la zone d'accès aux tables L2
 * Version intégrée dans le setup kernel
 */
static void setup_l2_access_zone(void)
{
    uint32_t split_boundary = get_split_boundary();
    
    /* Vérifier que cette adresse est dans notre plage */
    if (L2_CONTROL_VADDR < split_boundary || L2_CONTROL_VADDR >= 0x80000000) {
        panic("L2_CONTROL_VADDR outside valid kernel range");
    }
    
    /* Calculer les indices */
    uint32_t ttbr1_index = get_L1_index(L2_CONTROL_VADDR);
    uint32_t array_index = ttbr1_index;
    
    /* Allouer la table L2 pour la zone de contrôle */
    uint32_t* control_l2 = (uint32_t*)allocate_physical_page();
    if (!control_l2) {
        panic("Cannot allocate L2 control table");
    }
    memset(control_l2, 0, PAGE_SIZE);
    
    /* Installer l'entrée L1 */
    extern uint32_t* kernel_pgdir;
    kernel_pgdir[array_index] = ((uint32_t)control_l2 & 0xFFFFFC00) | 0x01;
    
    //kprintf("L2 control zone: L1[%u]=0x%08X\n", array_index, kernel_pgdir[array_index]);
    
    /* Allouer la page contenant les adresses des tables L2 */
    uint32_t* control_page = (uint32_t*)allocate_physical_page();
    if (!control_page) {
        panic("Cannot allocate L2 control page");
    }
    memset(control_page, 0, PAGE_SIZE);
    
    /* Remplir avec les adresses des tables L2 */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        control_page[i] = preallocated_l2_tables[i].phys_addr;
       //kprintf("Control page[%d] = 0x%08X (L2 table for slot %d)\n", 
         //      i, control_page[i], i);
    }
    
    /* Mapper la page de contrôle */
    uint32_t control_l2_index = L2_INDEX(L2_CONTROL_VADDR);
    control_l2[control_l2_index] = ((uint32_t)control_page & 0xFFFFF000) | 0x02 | 0x30 | 0x0C;
    
    /* Créer des mappings pour chaque table L2 */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        uint32_t l2_vaddr = L2_CONTROL_VADDR + 0x1000 + (i * 0x1000);
        uint32_t l2_l2_index = L2_INDEX(l2_vaddr);
        
        /* Mapper la table L2 à son adresse virtuelle dédiée */
        control_l2[l2_l2_index] = (control_page[i] & 0xFFFFF000) | 0x02 | 0x30 | 0x0C;
        
        /* Sauvegarder l'adresse virtuelle */
        l2_table_addresses[i] = (uint32_t*)l2_vaddr;
        
        //kprintf("L2 table %d accessible at vaddr 0x%08X\n", i, l2_vaddr);
    }
    
    //kprintf("L2 access zone configured at 0x%08X\n", L2_CONTROL_VADDR);
}


/**
 * setup_temp_mapping_slots - Configuration des slots de mapping temporaire
 * Appelée depuis setup_kernel_space() au bon moment
 */
void setup_temp_mapping_slots(void)
{
    //uint32_t split_boundary = get_split_boundary();
    
    /* Vérifier que nos constantes sont cohérentes */
    if (TEMP_MAP_BASE_VADDR != 0x80000000) {
        panic("TEMP_MAP_BASE_VADDR not aligned with TEMP_MAPPING_START");
    }
    
    /* 1. Allouer la zero page */
    uint32_t* zero_page = (uint32_t*)allocate_physical_page();
    if (!zero_page) {
        panic("Cannot allocate zero page for temp mappings");
    }
    memset(zero_page, 0, PAGE_SIZE);  // OK car identity mapping actif
    multi_temp_state.zero_page_phys = zero_page;
    
    //kprintf("Allocated zero page at 0x%08X\n", (uint32_t)zero_page);
    
    /* 2. Pour chaque slot de temp mapping */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        uint32_t vaddr = TEMP_MAP_BASE_VADDR + (i * TEMP_MAP_L1_SPACING);
        uint32_t ttbr1_index = get_L1_index(vaddr);
        uint32_t l2_index = L2_INDEX(vaddr);  // Devrait être 0
        
        //kprintf("Setting up temp slot %d: vaddr=0x%08X, L1_idx=%u (array[%u])\n", 
        //       i, vaddr, ttbr1_index, array_index);
        
        /* Allouer la table L2 */
        uint32_t* l2_phys = (uint32_t*)allocate_physical_page();
        if (!l2_phys) {
            panic("Cannot allocate L2 table for temp slot");
        }
        
        /* Vérifier alignement */
        if ((uint32_t)l2_phys & 0x3FF) {
            panic("L2 table not aligned");
        }
        
        /* Initialiser la table L2 */
        memset(l2_phys, 0, PAGE_SIZE);  // OK car identity mapping actif
        
        /* Configurer l'entrée L2 pour pointer vers la zero page */
        uint32_t page_flags = 0x02 |    /* Small page */
                             0x30 |    /* AP = 11 (kernel RW) */
                             0x0C;     /* Cacheable + bufferable */
        
        l2_phys[l2_index] = ((uint32_t)zero_page & 0xFFFFF000) | page_flags;
        
        /* Installer l'entrée L1 dans kernel_page_dir */
        extern uint32_t* kernel_pgdir;
        kernel_pgdir[ttbr1_index] = ((uint32_t)l2_phys & 0xFFFFFC00) | 0x01;
        
        /* Sauvegarder les infos */
        preallocated_l2_tables[i].phys_addr = (uint32_t)l2_phys;
        preallocated_l2_tables[i].initialized = true;
        
        //kprintf("Temp slot %d: L1[%u]=0x%08X, L2=0x%08X, L2[%u]=0x%08X\n", 
        //       i, array_index, kernel_pgdir[array_index], (uint32_t)l2_phys,
        //       l2_index, l2_phys[l2_index]);
    }
    
    /* 3. Créer la zone d'accès aux tables L2 */
    setup_l2_access_zone();
    
    kprintf("All temporary mapping slots configured successfully\n");
}

/**
 * init_temp_mapping_system - Initialisation finale du système
 * À appeler APRÈS l'activation de la MMU
 */
void init_temp_mapping_system(void)
{
    /* Initialiser l'état runtime */
    init_multi_temp_mapping_state();
    
    /* Valider la configuration */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (!validate_temp_slot_configuration(i)) {
            panic("Temp mapping slot validation failed");
        }
    }
    
    kprintf("Temporary mapping system initialized and validated\n");
    //debug_all_temp_slots();
}

/**
 * preallocate_temp_mapping_system - Configuration complète au boot
 * 
 * DOIT être appelée pendant le boot du kernel, avant que la MMU soit
 * complètement configurée et qu'on perde l'identity mapping.
 */
void preallocate_temp_mapping_system(void)
{
    uint32_t* kernel_pgdir;
    uint32_t* zero_page;
    
    KDEBUG("=== SETTING UP COMPLETE TEMP MAPPING SYSTEM ===\n");
    
    /* Initialiser le zero page d'abord */
    zero_page = get_zero_page_phys();
    if (!zero_page) {
        panic("Cannot allocate zero page for temp mappings");
    }
    
    /* Récupérer la table L1 kernel */
    kernel_pgdir = get_kernel_pgdir();
    if (!kernel_pgdir) {
        panic("Cannot get kernel page directory for temp mapping setup");
    }
    
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        uint32_t vaddr = TEMP_MAP_BASE_VADDR + (i * TEMP_MAP_L1_SPACING);
        uint32_t l1_index = get_L1_index(vaddr);
        uint32_t l2_index = L2_INDEX(vaddr);  /* Devrait être 0 pour nos adresses */
        
        KDEBUG("Setting up slot %d: vaddr=0x%08X, L1[%u], L2[%u]\n", 
               i, vaddr, l1_index, l2_index);
        
        /* 1. Allouer la table L2 */
        uint32_t* l2_phys = (uint32_t*)allocate_physical_page();
        if (!l2_phys) {
            panic("Cannot allocate L2 table for temp mappings");
        }
        
        /* Vérifier l'alignement */
        if ((uint32_t)l2_phys & 0x3FF) {
            panic("L2 table not properly aligned");
        }
        
        /* 2. Initialiser la table L2 (pendant qu'on a l'identity mapping) */
        memset(l2_phys, 0, PAGE_SIZE);
        
        /* 3. Configurer l'entrée L2 pour pointer vers la zero page initialement */
        uint32_t page_flags = 0x02 |    /* Small page */
                             0x30 |    /* AP = 11 (kernel RW) */
                             0x0C;     /* Cacheable + bufferable */
        
        l2_phys[l2_index] = ((uint32_t)zero_page & 0xFFFFF000) | page_flags;
        
        /* 4. Configurer l'entrée L1 dans TTBR1 */
        if (kernel_pgdir[l1_index] & PDE_PRESENT) {
            KWARN("L1[%u] already exists for slot %d\n", l1_index, i);
            uint32_t existing_l2 = kernel_pgdir[l1_index] & 0xFFFFFC00;
            if (existing_l2 != (uint32_t)l2_phys) {
                panic("L1 conflict: exists");
            }
        } else {
            kernel_pgdir[l1_index] = ((uint32_t)l2_phys & 0xFFFFFC00) | 0x01;
        }
        
        /* 5. Sauvegarder les informations */
        preallocated_l2_tables[i].phys_addr = (uint32_t)l2_phys;
        preallocated_l2_tables[i].initialized = true;
        
        KDEBUG("Slot %d configured: L1[%u]=0x%08X, L2=0x%08X, L2[%u]=0x%08X\n", 
               i, l1_index, kernel_pgdir[l1_index], (uint32_t)l2_phys, 
               l2_index, l2_phys[l2_index]);
    }
    
    /* Invalider tout le TLB */
    invalidate_tlb_all();
    data_sync_barrier();
    instruction_sync_barrier();
    
    KDEBUG("=== TEMP MAPPING SYSTEM FULLY CONFIGURED ===\n");
    KDEBUG("All slots are pre-mapped to zero page and ready for use\n");
}

/**
 * init_multi_temp_mapping_state - Initialize multi-slot temp mapping system
 */
static void init_multi_temp_mapping_state(void)
{
    if (multi_temp_state.initialized) {
        return;
    }
    
    init_spinlock(&multi_temp_state.lock);
    
    /* Initialize all slots */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        multi_temp_state.slots[i].virt_addr = TEMP_MAP_BASE_VADDR + (i * TEMP_MAP_L1_SPACING);
        multi_temp_state.slots[i].phys_addr = (uint32_t)multi_temp_state.zero_page_phys;
        multi_temp_state.slots[i].in_use = false;
    }
    
    multi_temp_state.saved_asid.saved_asid = 0;
    multi_temp_state.saved_asid.context_switched = false;
    multi_temp_state.saved_asid.saved_ttbr0 = get_ttbr0();
    multi_temp_state.initialized = true;
    
    KDEBUG("Multi-temp mapping runtime state initialized\n");
}


/**
 * create_l2_access_zone - Créer une zone accessible pour modifier les L2
 */
void create_l2_access_zone(void)
{
    /* Allouer une page pour stocker les adresses des tables L2 */
    uint32_t* control_page = (uint32_t*)allocate_physical_page();
    if (!control_page) {
        panic("Cannot allocate L2 control page");
    }
    
    /* Initialiser avec les adresses des tables L2 */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        control_page[i] = preallocated_l2_tables[i].phys_addr;
    }
    
    uint32_t* kernel_pgdir = get_kernel_pgdir();
    uint32_t control_l1_index = get_L1_index(L2_CONTROL_VADDR);
    
    /* Créer une table L2 pour la zone de contrôle */
    uint32_t* control_l2 = (uint32_t*)allocate_physical_page();
    memset(control_l2, 0, PAGE_SIZE);
    
    /* Configurer L1 pour la zone de contrôle */
    kernel_pgdir[control_l1_index] = ((uint32_t)control_l2 & 0xFFFFFC00) | 0x01;
    
    /* Configurer L2 pour mapper la page de contrôle */
    uint32_t control_l2_index = L2_INDEX(L2_CONTROL_VADDR);
    control_l2[control_l2_index] = ((uint32_t)control_page & 0xFFFFF000) | 0x02 | 0x30 | 0x0C;
    
    /* Maintenant L2_CONTROL_VADDR pointe vers la page contenant les adresses des tables L2 */
    uint32_t* l2_addresses_virt = (uint32_t*)L2_CONTROL_VADDR;
    
    /* Créer des mappings virtuels pour chaque table L2 */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        uint32_t l2_vaddr = L2_CONTROL_VADDR + 0x1000 + (i * 0x1000);  /* Adresses suivantes */
        uint32_t l2_l2_index = L2_INDEX(l2_vaddr);
        
        /* Mapper chaque table L2 à son adresse virtuelle dédiée */
        control_l2[l2_l2_index] = (l2_addresses_virt[i] & 0xFFFFF000) | 0x02 | 0x30 | 0x0C;
        
        /* Sauvegarder l'adresse virtuelle */
        l2_table_addresses[i] = (uint32_t*)l2_vaddr;
        
        KDEBUG("L2 table %d: phys=0x%08X -> virt=0x%08X\n", 
               i, l2_addresses_virt[i], l2_vaddr);
    }
    
    KDEBUG("L2 access zone created at 0x%08X\n", L2_CONTROL_VADDR);
}


/**
 * find_free_temp_slot - Find a free temporary mapping slot
 * Returns: slot index or -1 if none available
 */
static int find_free_temp_slot(void)
{
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (!multi_temp_state.slots[i].in_use) {
            return i;
        }
    }
    return -1;
}

/**
 * find_temp_slot_by_vaddr - Find slot by virtual address
 * @vaddr: Virtual address to search for
 * Returns: slot index or -1 if not found
 */
static int find_temp_slot_by_vaddr(uint32_t vaddr)
{
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (multi_temp_state.slots[i].in_use && 
            multi_temp_state.slots[i].virt_addr == vaddr) {
            return i;
        }
    }
    return -1;
}

/**
 * setup_temp_slot_mapping - Setup page table entry for a temp slot
 * @slot: Slot to setup
 * @phys_addr: Physical address to map
 */
static bool setup_temp_slot_mapping(int slot, uint32_t phys_addr)
{
    if (slot < 0 || slot >= MAX_TEMP_MAPPINGS) {
        KERROR("setup_temp_slot_mapping: Invalid slot %d\n", slot);
        return false;
    }
    
    if (!l2_table_addresses[slot]) {
        KERROR("setup_temp_slot_mapping: L2 access not configured for slot %d\n", slot);
        return false;
    }
    
    temp_mapping_slot_t* temp_slot = &multi_temp_state.slots[slot];
    uint32_t* l2_table_virt = l2_table_addresses[slot];  /* Adresse virtuelle de la table L2 ! */
    uint32_t l2_index = L2_INDEX(temp_slot->virt_addr);
    
    /* Maintenant on peut accéder directement à la table L2 ! */
    uint32_t page_flags = 0x02 |    /* Small page */
                         0x30 |    /* AP = 11 (kernel RW) */
                         0x0C;     /* Cacheable + bufferable */
    
    l2_table_virt[l2_index] = (phys_addr & 0xFFFFF000) | page_flags;
    
    /* Barrières mémoire */
    data_sync_barrier();
    
    KDEBUG("setup_temp_slot_mapping: L2[%u] = 0x%08X for slot %d\n", 
           l2_index, l2_table_virt[l2_index], slot);
    
    /* Invalider le TLB pour cette adresse */
    invalidate_tlb_page(temp_slot->virt_addr);
    data_sync_barrier();
    instruction_sync_barrier();
    
    return true;
}

void unmap_temp_pages_contiguous(uint32_t base_vaddr, int num_pages)
{
    if (num_pages > 4 || num_pages < 1) {
        KERROR("unmap_temp_pages_contiguous: Invalid num_pages %d\n", num_pages);
        return;
    }
    
    if (!multi_temp_state.initialized) {
        return;
    }
    
    //KDEBUG("unmap_temp_pages_contiguous: Unmapping %d pages starting at 0x%08X\n", 
    //       num_pages, base_vaddr);
    
    spin_lock(&multi_temp_state.lock);
    
    // Trouver le slot correspondant à cette adresse de base
    int slot = -1;
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (multi_temp_state.slots[i].virt_addr == base_vaddr && 
            multi_temp_state.slots[i].in_use) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        KERROR("unmap_temp_pages_contiguous: Base address 0x%08X not found\n", base_vaddr);
        spin_unlock(&multi_temp_state.lock);
        return;
    }
    
    //KDEBUG("unmap_temp_pages_contiguous: Found slot %d for base 0x%08X\n", slot, base_vaddr);
    
    // Obtenir la table L2 pour ce slot
    uint32_t* l2_table = l2_table_addresses[slot];
    if (!l2_table) {
        KERROR("unmap_temp_pages_contiguous: No L2 table for slot %d\n", slot);
        spin_unlock(&multi_temp_state.lock);
        return;
    }
    
    // Unmapper toutes les pages contiguës
    for (int i = 0; i < num_pages; i++) {
        uint32_t page_vaddr = base_vaddr + (i * PAGE_SIZE);
        uint32_t l2_index = L2_INDEX(page_vaddr);
        
        //KDEBUG("unmap_temp_pages_contiguous: Unmapping page %d at 0x%08X (L2[%u])\n", 
        //       i, page_vaddr, l2_index);
        
        // Remettre sur la zero page
        uint32_t page_flags = 0x02 | 0x10 | 0x0C | 0x01;  // Small, Priv RW, Cache, XN
        l2_table[l2_index] = ((uint32_t)multi_temp_state.zero_page_phys & 0xFFFFF000) | page_flags;
        
        // Invalider le TLB pour cette page
        invalidate_tlb_page(page_vaddr);
    }
    
    // Barrières mémoire
    data_sync_barrier();
    instruction_sync_barrier();
    
    // Marquer le slot comme libre
    multi_temp_state.slots[slot].phys_addr = (uint32_t)multi_temp_state.zero_page_phys;
    multi_temp_state.slots[slot].in_use = false;
    
    spin_unlock(&multi_temp_state.lock);
    
    //KDEBUG("unmap_temp_pages_contiguous: Successfully unmapped %d pages from slot %d\n", 
    //       num_pages, slot);
}

uint32_t map_temp_pages_contiguous(uint32_t phys_addr, int num_pages)
{
    if (num_pages > 4) {  // Max 4 pages consécutives par slot
        KERROR("map_temp_pages_contiguous: Too many pages %d\n", num_pages);
        return 0;
    }
    
    spin_lock(&multi_temp_state.lock);
    
    // Trouver un slot libre
    int slot = find_free_temp_slot();
    if (slot < 0) {
        spin_unlock(&multi_temp_state.lock);
        panic("find_free_temp_slot returned 0 !!!");
        return 0;
    }
    
    uint32_t base_vaddr = multi_temp_state.slots[slot].virt_addr;
    //KDEBUG("map_temp_pages_contiguous: base_vaddr 0x%08X for slot %u\n", base_vaddr, slot);
    
    // Mapper toutes les pages dans ce slot de manière contiguë
    for (int i = 0; i < num_pages; i++) {
        uint32_t page_phys = phys_addr + (i * PAGE_SIZE);
        uint32_t page_vaddr = base_vaddr + (i * PAGE_SIZE);
        
        // Configurer directement la table L2 du slot
        uint32_t* l2_table = l2_table_addresses[slot];
        uint32_t l2_index = L2_INDEX(page_vaddr);
        
        uint32_t page_flags = 0x02 | 0x10 | 0x0C | 0x01;  // Small, Priv RW, Cache, XN
        l2_table[l2_index] = (page_phys & 0xFFFFF000) | page_flags;
        
        invalidate_tlb_page(page_vaddr);
    }
    
    multi_temp_state.slots[slot].phys_addr = phys_addr;
    multi_temp_state.slots[slot].in_use = true;
    
    spin_unlock(&multi_temp_state.lock);
    
    return base_vaddr;
}

/**
 * map_temp_page_multi - Mapper plusieurs pages consécutives
 * @phys_addr: Adresse physique de départ (doit être alignée)
 * @num_pages: Nombre de pages à mapper (1-4)
 * Returns: Adresse virtuelle de la première page, ou 0 si échec
 */
uint32_t map_temp_page_multi(uint32_t phys_addr, int num_pages)
{
    if (num_pages < 1 || num_pages > MAX_TEMP_MAPPINGS) {
        KERROR("map_temp_pages_multi: Invalid num_pages %d (max %d)\n", 
               num_pages, MAX_TEMP_MAPPINGS);
        return 0;
    }
    
    if (phys_addr & (PAGE_SIZE - 1)) {
        KERROR("map_temp_pages_multi: Physical address 0x%08X not page-aligned\n", phys_addr);
        return 0;
    }
    
    KDEBUG("map_temp_pages_multi: Mapping %d pages starting at 0x%08X\n", 
           num_pages, phys_addr);
    
    spin_lock(&multi_temp_state.lock);
    
    /* Vérifier qu'on a assez de slots consécutifs libres */
    int start_slot = -1;
    for (int i = 0; i <= MAX_TEMP_MAPPINGS - num_pages; i++) {
        bool slots_available = true;
        for (int j = 0; j < num_pages; j++) {
            if (multi_temp_state.slots[i + j].in_use) {
                slots_available = false;
                break;
            }
        }
        if (slots_available) {
            start_slot = i;
            break;
        }
    }
    
    if (start_slot < 0) {
        KERROR("map_temp_pages_multi: Not enough consecutive slots for %d pages\n", num_pages);
        spin_unlock(&multi_temp_state.lock);
        return 0;
    }
    
    KDEBUG("map_temp_pages_multi: Using slots %d-%d\n", start_slot, start_slot + num_pages - 1);
    
    /* Mapper chaque page */
    for (int i = 0; i < num_pages; i++) {
        int slot_idx = start_slot + i;
        uint32_t page_phys = phys_addr + (i * PAGE_SIZE);
        
        if (!setup_temp_slot_mapping(slot_idx, page_phys)) {
            KERROR("map_temp_pages_multi: Failed to setup slot %d\n", slot_idx);
            
            /* Annuler les mappings déjà faits */
            for (int j = 0; j < i; j++) {
                int cleanup_slot = start_slot + j;
                setup_temp_slot_mapping(cleanup_slot, (uint32_t)multi_temp_state.zero_page_phys);
                multi_temp_state.slots[cleanup_slot].in_use = false;
            }
            
            spin_unlock(&multi_temp_state.lock);
            return 0;
        }
        
        /* Marquer le slot comme utilisé */
        multi_temp_state.slots[slot_idx].phys_addr = page_phys;
        multi_temp_state.slots[slot_idx].in_use = true;
        
        KDEBUG("map_temp_pages_multi: Mapped page %d: 0x%08X -> 0x%08X (slot %d)\n", 
               i, page_phys, multi_temp_state.slots[slot_idx].virt_addr, slot_idx);
    }
    
    uint32_t base_vaddr = multi_temp_state.slots[start_slot].virt_addr;
    
    spin_unlock(&multi_temp_state.lock);
    
    KDEBUG("map_temp_pages_multi: Successfully mapped %d pages at 0x%08X\n", 
           num_pages, base_vaddr);
    
    return base_vaddr;
}

/**
 * unmap_temp_page_multi - Démapper plusieurs pages consécutives
 * @base_vaddr: Adresse virtuelle de la première page
 * @num_pages: Nombre de pages à démapper
 */
void unmap_temp_page_multi(uint32_t base_vaddr, int num_pages)
{
    if (num_pages < 1 || num_pages > MAX_TEMP_MAPPINGS) {
        KERROR("unmap_temp_pages_multi: Invalid num_pages %d\n", num_pages);
        return;
    }
    
    if (!multi_temp_state.initialized) {
        return;
    }
    
    KDEBUG("unmap_temp_pages_multi: Unmapping %d pages starting at 0x%08X\n", 
           num_pages, base_vaddr);
    
    spin_lock(&multi_temp_state.lock);
    
    /* Trouver le slot de départ */
    int start_slot = -1;
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (multi_temp_state.slots[i].virt_addr == base_vaddr && 
            multi_temp_state.slots[i].in_use) {
            start_slot = i;
            break;
        }
    }
    
    if (start_slot < 0) {
        KERROR("unmap_temp_pages_multi: Base address 0x%08X not found\n", base_vaddr);
        spin_unlock(&multi_temp_state.lock);
        return;
    }
    
    /* Vérifier que tous les slots consécutifs sont utilisés */
    for (int i = 0; i < num_pages; i++) {
        int slot_idx = start_slot + i;
        if (slot_idx >= MAX_TEMP_MAPPINGS || !multi_temp_state.slots[slot_idx].in_use) {
            KERROR("unmap_temp_pages_multi: Slot %d not in use\n", slot_idx);
            spin_unlock(&multi_temp_state.lock);
            return;
        }
    }
    
    /* Démapper chaque page */
    for (int i = 0; i < num_pages; i++) {
        int slot_idx = start_slot + i;
        temp_mapping_slot_t* slot = &multi_temp_state.slots[slot_idx];
        
        KDEBUG("unmap_temp_pages_multi: Unmapping slot %d (0x%08X -> 0x%08X)\n", 
               slot_idx, slot->virt_addr, slot->phys_addr);
        
        /* Remettre sur la zero page */
        setup_temp_slot_mapping(slot_idx, (uint32_t)multi_temp_state.zero_page_phys);
        
        /* Marquer comme libre */
        slot->phys_addr = (uint32_t)multi_temp_state.zero_page_phys;
        slot->in_use = false;
    }
    
    spin_unlock(&multi_temp_state.lock);
    
    KDEBUG("unmap_temp_pages_multi: Successfully unmapped %d pages\n", num_pages);
}

/**
 * map_temp_page_large - Mapper une structure plus grande qu'une page
 * @phys_addr: Adresse physique de départ
 * @size: Taille en bytes (sera arrondie aux pages supérieures)
 * Returns: Adresse virtuelle ou 0 si échec
 */
uint32_t map_temp_page_large(uint32_t phys_addr, uint32_t size)
{
    /* Calculer le nombre de pages nécessaires */
    int num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    
    KDEBUG("map_temp_page_large: Size %u bytes = %d pages\n", size, num_pages);
    
    return map_temp_pages_contiguous(phys_addr, num_pages);
}

/**
 * unmap_temp_page_large - Démapper une structure large
 * @base_vaddr: Adresse virtuelle de départ
 * @size: Taille originale en bytes
 */
void unmap_temp_page_large(uint32_t base_vaddr, uint32_t size)
{
    int num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    unmap_temp_pages_contiguous(base_vaddr, num_pages);
}

/**
 * map_temp_page_multi - Map a physical page to temporary virtual address (multi-slot)
 * @phys_addr: Physical address to map (must be page-aligned)
 * 
 * Returns: Virtual address of mapped page, or 0 on failure
 */
uint32_t map_temp_page_multi2(uint32_t phys_addr)
{
    bool switched_context = false;
    int slot_idx;
    temp_mapping_slot_t* slot;
    
    /* Initialize if needed */
    if (!multi_temp_state.initialized) {
        init_multi_temp_mapping_state();
    }
    
    /* Validate input */
    if (phys_addr & (PAGE_SIZE - 1)) {
        KERROR("map_temp_page_simplified: Physical address 0x%08X not page-aligned\n", phys_addr);
        return 0;
    }
    
    KDEBUG("map_temp_page_simplified: Getting temp page for 0x%08X\n", phys_addr);
    
    /* Acquire lock */
    spin_lock(&multi_temp_state.lock);
    
    /* Find free slot */
    slot_idx = -1;
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (!multi_temp_state.slots[i].in_use) {
            slot_idx = i;
            break;
        }
    }
    
    if (slot_idx < 0) {
        KERROR("map_temp_page_simplified: No free temporary mapping slots\n");
        spin_unlock(&multi_temp_state.lock);
        return 0;
    }
    
    slot = &multi_temp_state.slots[slot_idx];
    
    /* Switch to kernel context if this is the first mapping */
    //if (multi_temp_state.saved_asid == 0) {
    //    switched_context = switch_to_kernel_context();
    //    if (switched_context) {
    //        multi_temp_state.saved_asid = get_current_asid();
    //    }
    //}
    kernel_context_save_t save = switch_to_kernel_context();
    if (save.context_switched) {
            switched_context = save.context_switched;
            multi_temp_state.saved_asid = save;
    }
    
    /* Setup the mapping using the simplified method */
    if (!setup_temp_slot_mapping(slot_idx, phys_addr)) {
        KERROR("map_temp_page_simplified: Failed to setup mapping for slot %d\n", slot_idx);
        goto error_exit;
    }
    
    /* Mark slot as in use */
    slot->phys_addr = phys_addr;
    slot->in_use = true;
    
    spin_unlock(&multi_temp_state.lock);
    
    KDEBUG("map_temp_page_simplified: Mapped 0x%08X to 0x%08X (slot %d)\n", 
           phys_addr, slot->virt_addr, slot_idx);
    
    return slot->virt_addr;

error_exit:
    if (switched_context && multi_temp_state.saved_asid.saved_asid != 0) {
        restore_from_kernel_context(save);
        multi_temp_state.saved_asid.context_switched = false;
        multi_temp_state.saved_asid.saved_asid = 0;
    }
    
    spin_unlock(&multi_temp_state.lock);
    return 0;
}

/**
 * unmap_temp_page_multi - Unmap a temporary page mapping (multi-slot)
 * @temp_vaddr: Virtual address returned by map_temp_page_multi
 */
void unmap_temp_page_multi2(void* temp_vaddr)
{
    uint32_t vaddr = (uint32_t)temp_vaddr;
    int slot_idx = -1;
    bool all_slots_free = true;
    
    if (!multi_temp_state.initialized) {
        return;
    }
    
    /* Find the slot */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (multi_temp_state.slots[i].virt_addr == vaddr && multi_temp_state.slots[i].in_use) {
            slot_idx = i;
            break;
        }
    }
    
    if (slot_idx < 0) {
        KDEBUG("unmap_temp_page: Address 0x%08X not found in active slots\n", vaddr);
        return;
    }
    
    spin_lock(&multi_temp_state.lock);
    
    temp_mapping_slot_t* slot = &multi_temp_state.slots[slot_idx];
    
    KDEBUG("unmap_temp_page: Unmapping slot %d (0x%08X -> 0x%08X)\n", 
           slot_idx, slot->virt_addr, slot->phys_addr);
    
    /* Remettre le slot sur la zero page */
    setup_temp_slot_mapping(slot_idx, (uint32_t)multi_temp_state.zero_page_phys);
    
    /* Mark slot as free */
    slot->phys_addr = (uint32_t)multi_temp_state.zero_page_phys;
    slot->in_use = false;
    
    /* Check if all slots are now free */
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        if (multi_temp_state.slots[i].in_use) {
            all_slots_free = false;
            break;
        }
    }
    
    /* If all slots are free, restore user context */
    if (all_slots_free && multi_temp_state.saved_asid.saved_asid != 0) {
        restore_from_kernel_context(multi_temp_state.saved_asid);
        multi_temp_state.saved_asid.saved_asid = 0;
        multi_temp_state.saved_asid.context_switched = false;
    }
    
    spin_unlock(&multi_temp_state.lock);
    
    KDEBUG("unmap_temp_page: Slot %d unmapped successfully\n", slot_idx);
}

/**
 * Wrapper functions pour compatibilité avec l'ancien système
 */
uint32_t map_temp_page(uint32_t phys_addr)
{
    return map_temp_pages_contiguous(phys_addr,1);
}

void unmap_temp_page(void* temp_vaddr)
{
    unmap_temp_pages_contiguous((uint32_t)temp_vaddr,1);
}

/**
 * get_temp_page_table_for_slot - Get or create L2 table for a specific slot
 * @slot: Slot index
 * Returns: Pointer to L2 table or NULL on failure
 */
static uint32_t* get_temp_page_table_for_slot(int slot)
{
    /* Validation */
    if (slot < 0 || slot >= MAX_TEMP_MAPPINGS) {
        KERROR("get_temp_page_table_for_slot: Invalid slot %d\n", slot);
        return NULL;
    }
    
    /* Vérifier que le slot a été pré-configuré */
    if (!preallocated_l2_tables[slot].initialized) {
        KERROR("get_temp_page_table_for_slot: Slot %d not pre-configured\n", slot);
        KERROR("Did you call preallocate_temp_mapping_system() during boot?\n");
        return NULL;
    }
    
    /* Retourner directement l'adresse physique pré-allouée */
    uint32_t* l2_phys = (uint32_t*)preallocated_l2_tables[slot].phys_addr;
    
    KDEBUG("get_temp_page_table_for_slot: Using pre-allocated L2 for slot %d: 0x%08X\n",
           slot, (uint32_t)l2_phys);
    
    return l2_phys;
}

/**
 * get_temp_page_table_virt_for_slot - Obtenir l'adresse VIRTUELLE de la table L2
 * @slot: Slot index  
 * Returns: Pointer to L2 table (VIRTUAL address) or NULL on failure
 * 
 * Cette fonction est utile quand on veut modifier la table L2 directement
 */
static uint32_t* get_temp_page_table_virt_for_slot(int slot)
{
    /* Validation */
    if (slot < 0 || slot >= MAX_TEMP_MAPPINGS) {
        KERROR("get_temp_page_table_virt_for_slot: Invalid slot %d\n", slot);
        return NULL;
    }
    
    /* Vérifier que la zone d'accès L2 a été configurée */
    if (!l2_table_addresses[slot]) {
        KERROR("get_temp_page_table_virt_for_slot: L2 access zone not configured for slot %d\n", slot);
        KERROR("Did you call create_l2_access_zone() during boot?\n");
        return NULL;
    }
    
    KDEBUG("get_temp_page_table_virt_for_slot: L2 virtual address for slot %d: 0x%08X\n",
           slot, (uint32_t)l2_table_addresses[slot]);
    
    return l2_table_addresses[slot];
}

/**
 * validate_temp_slot_configuration - Valider la configuration d'un slot
 * @slot: Slot to validate
 * Returns: true if slot is properly configured, false otherwise
 */
static bool validate_temp_slot_configuration(int slot)
{
    if (slot < 0 || slot >= MAX_TEMP_MAPPINGS) {
        KERROR("validate_temp_slot_configuration: Invalid slot %d\n", slot);
        return false;
    }
    
    //KDEBUG("=== VALIDATING SLOT %d CONFIGURATION ===\n", slot);
    
    /* Vérifier que la table L2 physique existe */
    if (!preallocated_l2_tables[slot].initialized) {
        KERROR("Slot %d: L2 table not pre-allocated\n", slot);
        return false;
    }
    
    uint32_t* l2_phys = (uint32_t*)preallocated_l2_tables[slot].phys_addr;
    //KDEBUG("Slot %d: L2 physical table at 0x%08X\n", slot, (uint32_t)l2_phys);
    
    /* Vérifier que l'adresse virtuelle d'accès existe */
    if (!l2_table_addresses[slot]) {
        KERROR("Slot %d: L2 virtual access address not configured\n", slot);
        return false;
    }
    
    uint32_t* l2_virt = l2_table_addresses[slot];
    //KDEBUG("Slot %d: L2 virtual access at 0x%08X\n", slot, (uint32_t)l2_virt);
    
    /* Vérifier que l'entrée L1 existe */
    extern uint32_t* kernel_pgdir;
    //uint32_t* kernel_pgdir = get_kernel_pgdir();
    if (!kernel_pgdir) {
        KERROR("Slot %d: Cannot get kernel page directory\n", slot);
        return false;
    }
    
    uint32_t vaddr = TEMP_MAP_BASE_VADDR + (slot * TEMP_MAP_L1_SPACING);
    uint32_t l1_index = get_L1_index(vaddr);
    
    if (!(kernel_pgdir[l1_index] & PDE_PRESENT)) {
        KERROR("Slot %d: L1[%u] entry not present for vaddr 0x%08X - kernel_pgdir[l1_index] = 0x%08X\n", 
               slot, l1_index, vaddr,kernel_pgdir[l1_index]);
        return false;
    }
    
    uint32_t l1_l2_addr = kernel_pgdir[l1_index] & 0xFFFFFC00;
    if (l1_l2_addr != (uint32_t)l2_phys) {
        KERROR("Slot %d: L1[%u] points to 0x%08X but L2 is at 0x%08X\n", 
               slot, l1_index, l1_l2_addr, (uint32_t)l2_phys);
        return false;
    }
    
    //KDEBUG("Slot %d: L1[%u] = 0x%08X (correct)\n", 
    //       slot, l1_index, kernel_pgdir[l1_index]);
    
    /* Vérifier que l'entrée L2 pointe vers la zero page */
    uint32_t l2_index = L2_INDEX(vaddr);
    uint32_t l2_entry = l2_virt[l2_index];
    uint32_t expected_zero_page = (uint32_t)multi_temp_state.zero_page_phys & 0xFFFFF000;
    uint32_t actual_mapped_page = l2_entry & 0xFFFFF000;
    
    if (actual_mapped_page != expected_zero_page) {
        KWARN("Slot %d: L2[%u] points to 0x%08X, expected zero page 0x%08X\n", 
              slot, l2_index, actual_mapped_page, expected_zero_page);
        /* Ce n'est pas forcément une erreur si le slot est en cours d'utilisation */
    }
    
    //KDEBUG("Slot %d: L2[%u] = 0x%08X\n", slot, l2_index, l2_entry);
    
    //KDEBUG("=== SLOT %d VALIDATION COMPLETE ===\n", slot);
    return true;
}


/**
 * Debug function to show current temp mapping state
 */
void debug_temp_mappings(void)
{
    if (!multi_temp_state.initialized) {
        KDEBUG("Multi-temp mapping system not initialized\n");
        return;
    }
    
    spin_lock(&multi_temp_state.lock);
    
    KDEBUG("=== TEMP MAPPING STATE ===\n");
    KDEBUG("Saved ASID: %u\n", multi_temp_state.saved_asid);
    
    for (int i = 0; i < MAX_TEMP_MAPPINGS; i++) {
        temp_mapping_slot_t* slot = &multi_temp_state.slots[i];
        if (slot->in_use) {
            KDEBUG("Slot %d: 0x%08X -> 0x%08X \n", 
                   i, slot->virt_addr, slot->phys_addr);
        } else {
            KDEBUG("Slot %d: FREE (vaddr: 0x%08X)\n", i, slot->virt_addr);
        }
    }
    
    spin_unlock(&multi_temp_state.lock);
}

uint32_t map_temp_user_page(uint32_t phys_addr)
{
    uint32_t* kernel_pgdir = get_kernel_pgdir();
    uint32_t pgd_index = KERNEL_L1_INDEX(TEMP_USER_MAP_VADDR);
    uint32_t* l2_table;

    if (!IS_KERNEL_ADDR(TEMP_USER_MAP_VADDR)) {
        KERROR("TEMP_USER_MAP_VADDR not in kernel space\n");
        return 0;
    }

    spin_lock(&temp_map_state.lock);

    if (temp_map_state.in_use) {
        KERROR("Temporary mapping already in use!\n");
        spin_unlock(&temp_map_state.lock);
        return 0;
    }

    // Get or create L2
    l2_table = get_temp_page_table();  // réservé à TTBR1
    if (!l2_table) {
        spin_unlock(&temp_map_state.lock);
        return 0;
    }

    // Set up L2 entry
    setup_temp_page_table_entry(l2_table, phys_addr);

    // Setup L1 entry if missing
    if (!(kernel_pgdir[pgd_index] & PDE_PRESENT)) {
        kernel_pgdir[pgd_index] = ((uint32_t)l2_table & 0xFFFFFC00) | 0x01;
        invalidate_tlb_page(TEMP_USER_MAP_VADDR);
        data_sync_barrier();
        instruction_sync_barrier();
    }

    temp_map_state.in_use = true;
    temp_map_state.phys_addr = phys_addr;

    spin_unlock(&temp_map_state.lock);
    return TEMP_USER_MAP_VADDR;
}

void unmap_temp_user_page()
{
    spin_lock(&temp_map_state.lock);

    if (!temp_map_state.in_use) {
        spin_unlock(&temp_map_state.lock);
        return;
    }

    clear_temp_page_table_entry(get_temp_page_table());
    invalidate_tlb_page(TEMP_USER_MAP_VADDR);
    data_sync_barrier();
    instruction_sync_barrier();

    temp_map_state.in_use = false;
    temp_map_state.phys_addr = 0;

    spin_unlock(&temp_map_state.lock);
}

uint32_t get_phys_from_temp_mapping(uint32_t temp_ptr)
{
    return temp_map_state.phys_addr | (temp_ptr & 0xFFF);
}

/**
 * get_phys_addr_from_pgdir - Retourne l'adresse physique d'un vaddr depuis un pgdir donné.
 * @pgdir: Table de pages de niveau 1 (TTBR0 style)
 * @vaddr: Adresse virtuelle utilisateur à traduire
 * 
 * Cette fonction lit directement les entrées L1/L2 sans changer d'ASID ni de TTBR.
 * Elle est utile pour des cas comme fork/exec où l'on lit dans un autre espace mémoire.
 * 
 * Returns: adresse physique (uint32_t) ou 0 si non mappée
 */
uint32_t get_phys_addr_from_pgdir(uint32_t* pgdir, uint32_t vaddr)
{
    uint32_t l1_index = get_L1_index(vaddr);
    uint32_t l2_index = L2_INDEX(vaddr);
    uint32_t l1_entry = pgdir[l1_index];

    // Vérifier que c’est une coarse page table
    if ((l1_entry & 0x3) != 0x1) {
        return 0;
    }

    // Adresse physique de la L2 table
    uint32_t l2_phys = l1_entry & 0xFFFFFC00;

    // Mapper temporairement pour lire
    uint32_t l2_virt = map_temp_page(l2_phys);
    if (!l2_virt)
        return 0;

    uint32_t* l2_table = (uint32_t*)l2_virt;
    uint32_t l2_entry = l2_table[l2_index];

    unmap_temp_page((void*)l2_virt);

    // Vérifier que c’est une small page
    if ((l2_entry & 0x3) != 0x2) {
        return 0;
    }

    uint32_t phys_base = l2_entry & 0xFFFFF000;
    uint32_t offset    = OFFSET(vaddr);

    return phys_base + offset;
}

/**
 * map_temp_page - Map a physical page to temporary virtual address
 * @phys_addr: Physical address to map (must be page-aligned)
 * 
 * Maps a physical page to a temporary virtual address for kernel operations.
 * Avec split TTBR, cette fonction s'assure de travailler dans le contexte noyau.
 * 
 * Returns: Virtual address of mapped page, or 0 on failure
 */
uint32_t map_temp_page2(uint32_t phys_addr)
{
    uint32_t* kernel_pgdir;
    uint32_t* page_table;
    uint32_t pgd_index;
    bool switched_context = false;
    
    /* Initialize temp mapping state if needed */
    if (!is_temp_mapping_initialized()) {
        init_temp_mapping_state();
    }
    
    /* Validate input */
    if (phys_addr & (PAGE_SIZE - 1)) {
        uart_puts("map_temp_page: Physical address not page-aligned\n");
        return 0;
    }

    KDEBUG("map_temp_page: Getting temp page for 0x%08X\n", phys_addr);
    
    /* Acquire lock for thread safety */
    spin_lock(&temp_map_state.lock);
    
    /* Check if already in use */
    if (temp_map_state.in_use) {
        uart_puts("map_temp_page: Temporary mapping already in use\n");
        spin_unlock(&temp_map_state.lock);
        return 0;
    }
    
    /* S'assurer qu'on est dans le contexte noyau pour accéder à TTBR1 */
    kernel_context_save_t save = switch_to_kernel_context();
    switched_context = save.context_switched;
    
    /* Get kernel page directory (TTBR1) */
    kernel_pgdir = get_kernel_pgdir();
    if (!kernel_pgdir) {
        uart_puts("map_temp_page: Cannot get kernel page directory\n");
        if (switched_context) {
            restore_from_kernel_context(temp_map_state.saved_asid);
        }
        spin_unlock(&temp_map_state.lock);
        return 0;
    }

    /* Vérifier que l'adresse temporaire est dans l'espace noyau (TTBR1) */
    if (!IS_KERNEL_ADDR(TEMP_MAP_VADDR)) {
        KERROR("map_temp_page: Temp address 0x%08X not in kernel space\n", TEMP_MAP_VADDR);
        if (switched_context) {
            restore_from_kernel_context(temp_map_state.saved_asid);
        }
        spin_unlock(&temp_map_state.lock);
        return 0;
    }

    /* Calculate page directory index for TTBR1 */
    pgd_index = get_L1_index(TEMP_MAP_VADDR);
    
    KDEBUG("map_temp_page: Using kernel L1 index %u for temp mapping\n", pgd_index);
    
    /* Get or create page table */
    page_table = get_temp_page_table();
    if (!page_table) {
        if (switched_context) {
            restore_from_kernel_context(temp_map_state.saved_asid);
        }
        spin_unlock(&temp_map_state.lock);
        return 0;
    }
    
    /* Setup page table entry */
    setup_temp_page_table_entry(page_table, phys_addr);
    
    /* Ensure page directory entry exists in TTBR1 */
    if (!(kernel_pgdir[pgd_index] & PDE_PRESENT)) {

        /* Page Directory Entry pour Cortex-A15 dans TTBR1 */
        kernel_pgdir[pgd_index] = ((uint32_t)page_table & 0xFFFFFC00) |  /* Adresse page table */
                                 0x01 |                                   /* Type = Coarse page table */
                                 0x00 |                                   /* Domain = 0 */
                                 0x00;                                    /* Pas de bits spéciaux */

        KDEBUG("map_temp_page: Created L1 entry in TTBR1[%u] = 0x%08X\n", 
               pgd_index, kernel_pgdir[pgd_index]);
        
        /* Invalidate TLB for this address (pas d'ASID pour le noyau) */
        invalidate_tlb_page(TEMP_MAP_VADDR);
        
        /* Memory barriers */
        data_sync_barrier();
        instruction_sync_barrier();

        KDEBUG("map_temp_page: TLB invalidation completed\n");
    }
    
    /* Mark as in use */
    temp_map_state.phys_addr = phys_addr;
    temp_map_state.in_use = true;

    /* Ne pas restaurer le contexte utilisateur ici - on le fait dans unmap */
    /* Le contexte noyau reste actif pour permettre l'accès au mapping temporaire */

    spin_unlock(&temp_map_state.lock);
    
    KDEBUG("map_temp_page: Successfully mapped 0x%08X to 0x%08X\n", 
           phys_addr, TEMP_MAP_VADDR);
    
    return TEMP_MAP_VADDR;
}

/**
 * unmap_temp_page - Unmap the temporary page mapping
 * @temp_vaddr: Virtual address returned by map_temp_page (ignored for safety)
 * 
 * Unmaps the current temporary page mapping avec support split TTBR.
 */
void unmap_temp_page2(void* temp_vaddr)
{
    uint32_t* page_table;
    
    /* Suppress unused parameter warning */
    (void)temp_vaddr;
    
    /* Acquire lock */
    spin_lock(&temp_map_state.lock);
    
    /* Check if actually in use */
    if (!temp_map_state.in_use) {
        spin_unlock(&temp_map_state.lock);
        return;
    }

    /* S'assurer qu'on est toujours dans le contexte noyau */
    /* (normalement déjà le cas depuis map_temp_page) */
    
    KDEBUG("unmap_temp_page: Unmapping temp page 0x%08X\n", TEMP_MAP_VADDR);
    
    /* Get page table */
    page_table = get_temp_page_table();
    if (page_table) {
        /* Clear page table entry */
        clear_temp_page_table_entry(page_table);
    }
    
    /* Invalidate TLB */
    invalidate_tlb_page(TEMP_MAP_VADDR);
    
    /* Memory barriers */
    data_sync_barrier();
    instruction_sync_barrier();

    /* Restaurer le contexte utilisateur si nécessaire */
    if (temp_map_state.saved_asid.saved_asid != 0) {
        restore_from_kernel_context(temp_map_state.saved_asid);
        temp_map_state.saved_asid.saved_asid = 0;
    }
    
    /* Mark as free */
    temp_map_state.phys_addr = 0;
    temp_map_state.in_use = false;
    
    spin_unlock(&temp_map_state.lock);
    
    KDEBUG("unmap_temp_page: Temp page unmapped successfully\n");
}

/**
 * zero_fill_bss - Zero-fill a BSS region in virtual memory
 * @vm: Virtual memory space to operate on
 * @vaddr: Virtual address start of BSS region
 * @size: Size of BSS region to zero
 * 
 * Mis à jour pour le support split TTBR et ASID.
 */
void zero_fill_bss(vm_space_t* vm, uint32_t vaddr, uint32_t size)
{
    uint32_t current_addr;
    uint32_t end_addr;
    uint32_t page_start;
    uint32_t page_offset;
    uint32_t bytes_to_zero;
    uint32_t phys_addr;
    uint32_t temp_vaddr;
    void* phys_page;
    uint32_t original_asid;
    
    if (!vm || size == 0) {
        return;
    }
    
    /* Vérifier que la région est dans l'espace utilisateur */
    if (vaddr >= TTBR0_MAX_ADDR || (vaddr + size) > TTBR0_MAX_ADDR) {
        uart_puts("zero_fill_bss: BSS region extends into kernel space\n");
        return;
    }
    
    /* Sauvegarder l'ASID actuel et switcher vers l'espace cible */
    original_asid = vm_get_current_asid();
    switch_to_vm_space(vm);
    
    current_addr = vaddr;
    end_addr = vaddr + size;
    
    uart_puts("zero_fill_bss: Zeroing BSS region 0x");
    uart_put_hex(vaddr);
    uart_puts(" size 0x");
    uart_put_hex(size);
    uart_puts(" in ASID ");
    uart_put_hex(vm->asid);
    uart_puts("\n");
    
    while (current_addr < end_addr) {
        /* Calculate page boundary */
        page_start = current_addr & ~(PAGE_SIZE - 1);
        page_offset = current_addr & (PAGE_SIZE - 1);
        
        /* Get physical address for this page */
        phys_addr = get_physical_address(vm->pgdir, page_start);
        
        if (phys_addr == 0) {
            /* Page not mapped, allocate and map it */
            phys_page = allocate_physical_page();
            if (!phys_page) {
                uart_puts("zero_fill_bss: Failed to allocate page\n");
                break;
            }
            
            /* Map the new page */
            if (vm->vma_list) {
                map_user_page(vm->pgdir, page_start, (uint32_t)phys_page, vm->vma_list->flags);
            } else {
                /* Permissions par défaut pour BSS */
                map_user_page(vm->pgdir, page_start, (uint32_t)phys_page, 
                             VMA_READ | VMA_WRITE);
            }
            phys_addr = (uint32_t)phys_page;
        }
        
        /* Map page temporarily for access */
        temp_vaddr = map_temp_page(phys_addr);
        if (temp_vaddr == 0) {
            uart_puts("zero_fill_bss: Failed to map temp page\n");
            break;
        }
        
        /* Calculate how many bytes to zero in this page */
        bytes_to_zero = MIN(PAGE_SIZE - page_offset, end_addr - current_addr);
        
        /* Zero the region */
        memset((void*)(temp_vaddr + page_offset), 0, bytes_to_zero);
        
        /* Unmap temporary mapping */
        unmap_temp_page((void*)temp_vaddr);
        
        /* Move to next page */
        current_addr += bytes_to_zero;
    }
    
    /* Restaurer l'ASID original */
    if (original_asid != vm->asid) {
        /* Code pour restaurer l'ASID - nécessite un VM space pour l'ASID original */
        KDEBUG("zero_fill_bss: Should restore original ASID %u\n", original_asid);
    }
    
    uart_puts("zero_fill_bss: Completed\n");
}

/* Static function implementations */

/**
 * init_temp_mapping_state - Initialize temporary mapping state
 */
static void init_temp_mapping_state(void)
{
    init_spinlock(&temp_map_state.lock);
    temp_map_state.phys_addr = 0;
    temp_map_state.in_use = false;
    temp_map_state.saved_asid.saved_asid = 0;
    temp_map_state.saved_asid.context_switched = false;
}

/**
 * get_current_pgdir - Get pointer to current page directory
 * Avec split TTBR, retourne TTBR0 ou TTBR1 selon l'adresse
 */
static uint32_t* get_current_pgdir(void)
{
    /* Pour les mappings temporaires dans l'espace noyau, utiliser TTBR1 */
    return get_kernel_pgdir();
}

/**
 * get_temp_page_table - Get page table for temporary mapping dans TTBR1
 */
static uint32_t* get_temp_page_table(void)
{
    uint32_t* kernel_pgdir;
    uint32_t pgd_index;
    uint32_t* page_table;
    
    kernel_pgdir = get_kernel_pgdir();
    if (!kernel_pgdir) {
        return NULL;
    }
    
    /* Index ajusté pour TTBR1 */
    pgd_index = get_L1_index(TEMP_MAP_VADDR);
    
    /* Check if page table exists */
    if (!(kernel_pgdir[pgd_index] & PDE_PRESENT)) {
        /* Allocate new page table */
        page_table = (uint32_t*)allocate_physical_page();
        if (!page_table) {
            return NULL;
        }
        
        /* Clear page table */
        //memset(page_table, 0, PAGE_SIZE);
        
        /* Install in kernel page directory (TTBR1) */
        kernel_pgdir[pgd_index] = ((uint32_t)page_table & 0xFFFFFC00) |  
                                 0x01 |    /* Coarse page table */
                                 0x00;     /* Domain = 0 */
        
        //KDEBUG("get_temp_page_table: Created new L2 table at 0x%08X\n", 
        //       (uint32_t)page_table);
    } else {
        /* Get existing page table */
        page_table = (uint32_t*)(kernel_pgdir[pgd_index] & ~0xFFF);
        //KDEBUG("get_temp_page_table: Using existing L2 table at 0x%08X\n", 
        //       (uint32_t)page_table);
    }
    
    return page_table;
}

/**
 * setup_temp_page_table_entry - Setup page table entry for temporary mapping
 * @pt: Page table pointer
 * @phys_addr: Physical address to map
 */
static void setup_temp_page_table_entry(uint32_t* pt, uint32_t phys_addr)
{
    uint32_t pte_index;
    
    pte_index = L2_INDEX(TEMP_MAP_VADDR);

    /* CORTEX-A15 : Format ARMv7 pour pages kernel */
    pt[pte_index] = (phys_addr & 0xFFFFF000) |  /* Adresse physique */
                    0x02 |                       /* XN=0, Type=Small page */
                    0x10 |                       /* AP[1:0] = 01 (Kernel RW) */
                    0x04 |                       /* B=1 (Bufferable) */
                    0x08;                        /* C=1 (Cacheable) */
    
    //KDEBUG("setup_temp_pte: L2[%u] = 0x%08X (phys=0x%08X)\n", 
    //       pte_index, pt[pte_index], phys_addr);
}

/**
 * clear_temp_page_table_entry - Clear page table entry for temporary mapping
 * @pt: Page table pointer
 */
static void clear_temp_page_table_entry(uint32_t* pt)
{
    uint32_t pte_index;
    
    pte_index = L2_INDEX(TEMP_MAP_VADDR);
    pt[pte_index] = 0;
    
    //KDEBUG("clear_temp_pte: Cleared L2[%u]\n", pte_index);
}

/**
 * is_temp_mapping_initialized - Check if temporary mapping state is initialized
 */
static bool is_temp_mapping_initialized(void)
{
    return temp_map_state.lock.locked == 0;
}

/**
 * switch_to_kernel_context - Switch to kernel context pour temp mapping
 * Retourne true si un switch a été effectué
 */
kernel_context_save_t switch_to_kernel_context(void)
{
    kernel_context_save_t save = {0};
    
    // Sauvegarder l'état actuel
    save.saved_ttbr0 = get_ttbr0();
    save.saved_asid = vm_get_current_asid();
    save.context_switched = true;
    
    KDEBUG("Switching to kernel pure context (ASID 0)\n");
    KDEBUG("  Saved TTBR0: 0x%08X, ASID: %u\n", save.saved_ttbr0, save.saved_asid);
    KDEBUG("  Kernel TTBR0: 0x%08X, ASID: %u\n", (uint32_t)ttbr0_pgdir, ASID_KERNEL);

    uint32_t ttbr1 = get_ttbr1();
  
    invalidate_tlb_asid(save.saved_asid);

    // Switch vers le contexte kernel pur
    set_ttbr0(ttbr1);  // TTBR0 kernel minimal
    set_current_asid(ASID_KERNEL);      // ASID 0
    KDEBUG("After set_current_asid\n");
    
    // Invalider le TLB pour s'assurer de la cohérence
    //invalidate_tlb_all();
    data_sync_barrier();
    instruction_sync_barrier();
    
    KDEBUG("Switched to kernel pure context successfully\n");
    
    return save;

}

void restore_from_kernel_context(kernel_context_save_t save){

    if (!save.context_switched) {
        return;  // Pas de switch effectué
    }
    
    KDEBUG("Restoring from kernel pure context\n");
    KDEBUG("  Restoring TTBR0: 0x%08X, ASID: %u\n", save.saved_ttbr0, save.saved_asid);

    /* Invalider tout le TLB */
    KDEBUG("Restoring from kernel pure context\n");
    invalidate_tlb_asid(ASID_KERNEL);

    set_current_asid(save.saved_asid);
    invalidate_tlb_asid(save.saved_asid);
    KDEBUG("");
    //data_sync_barrier();
    //instruction_sync_barrier();
    
    // Restaurer l'état original
    set_ttbr0(save.saved_ttbr0);

    
    // Invalider le TLB pour la transition
    //invalidate_tlb_all();
    //invalidate_tlb_asid(save.saved_asid);
    data_sync_barrier();
    instruction_sync_barrier();
    
    KDEBUG("Context restored successfully\n");

}

/**
 * restore_user_context - Restore user context après temp mapping
 */
void restore_user_context2(uint32_t saved_asid)
{
    if (saved_asid == 0) {
        return;  // Pas de switch effectué
    }
    
    KDEBUG("Restoring from kernel pure context\n");
    
    // Restaurer l'état original
    set_current_asid(saved_asid);
    
    // Invalider le TLB pour la transition
    invalidate_tlb_all();
    data_sync_barrier();
    instruction_sync_barrier();
    
    KDEBUG("Context restored successfully\n");
}

/**
 * Nouvelles fonctions helper pour split TTBR
 */

uint32_t* get_page_entry_arm(uint32_t* pgdir, uint32_t vaddr) {
    static uint32_t cached_entry = 0;
    uint32_t l1_index, l2_index;
    uint32_t* l1_entry;
    uint32_t* l2_table;
    
    /* Vérifier que l'adresse et le pgdir sont cohérents */
    if ( (vaddr)) {
        KERROR("get_page_entry_arm: Kernel address 0x%08X with user pgdir\n", vaddr);
        return NULL;
    }
    
    /* Index dans la table de niveau 1 (ajusté pour TTBR0) */
    l1_index = get_L1_index(vaddr);
    l1_entry = &pgdir[l1_index];
    
    KDEBUG("get_page_entry_arm: L1 index: %u, L1 entry: 0x%08X\n", l1_index, *l1_entry);
    
    /* Vérifier si l'entrée L1 est valide */
    if (!(*l1_entry & 0x1)) {
        KDEBUG("get_page_entry_arm: L1 entry not present\n");
        return NULL;
    }
    
    /* Vérifier le type d'entrée L1 */
    uint32_t l1_type = *l1_entry & 0x3;
    
    if (l1_type == 0x2) {
        /* Section 1MB - pas de table L2 */
        KDEBUG("get_page_entry_arm: 1MB section mapping\n");
        return l1_entry;
    }
    
    if (l1_type == 0x1) {
        /* Table de pages L2 */
        uint32_t l2_phys = *l1_entry & 0xFFFFFC00;
        
        /* Mapper temporairement */
        uint32_t l2_temp = map_temp_pages_contiguous(l2_phys,8);
        //uint32_t l2_temp = map_temp_page_large(l2_phys, 12*1024);
        if (l2_temp == 0) {
            KDEBUG("get_page_entry_arm: Failed to map L2 table temporarily\n");
            return NULL;
        }
        
        l2_table = (uint32_t*)l2_temp;
        
        /* Index dans la table L2 (bits 19:12) */
        l2_index = L2_INDEX(vaddr);
        
        KDEBUG("get_page_entry_arm: L2 table temp mapped at 0x%08X, L2 index: %u\n", 
               l2_temp, l2_index);
        
        /* Lire l'entrée et la cacher */
        cached_entry = l2_table[l2_index];
        
        /* Unmap immédiatement */
        unmap_temp_pages_contiguous(l2_temp,8);
        
        /* Retourner un pointeur vers l'entrée cachée */
        return &cached_entry;
    }
    
    KDEBUG("get_page_entry_arm: Invalid L1 entry type: %u\n", l1_type);
    return NULL;
}

/**
 * Vérifie si une adresse virtuelle est mappée et exécutable avec split TTBR
 */
int check_page_permissions(uint32_t* pgdir, uint32_t vaddr) {
    uint32_t* page_entry;
    
    /* Vérifier que l'adresse est dans le bon espace */
    if (IS_KERNEL_ADDR(vaddr)) {
        KERROR("check_page_permissions: Cannot check kernel address 0x%08X with user pgdir\n", 
               vaddr);
        return -1;
    }
    
    page_entry = get_page_entry_arm(pgdir, vaddr);
    
    if (!page_entry) {
        KERROR("check_page_permissions: Address 0x%08X not mapped\n", vaddr);
        return -1;
    }
    
    uint32_t entry = *page_entry;
    KDEBUG("check_page_permissions: Page entry for 0x%08X: 0x%08X\n", vaddr, entry);
    
    /* Vérifier le type d'entrée ARM */
    uint32_t entry_type = entry & 0x3;
    
    if (entry_type != 0x2) {  /* 0x2 = Small page */
        KERROR("check_page_permissions: Page not present or wrong type (type=0x%X) for address 0x%08X\n", 
               entry_type, vaddr);
        return -1;
    }
    
    /* Vérifier les permissions d'accès ARM */
    uint32_t ap = (entry >> 4) & 0x3;   /* Bits AP[1:0] dans les bits 5:4 */
    
    KDEBUG("check_page_permissions: Access permissions: AP=%u, entry_type=0x%X\n", ap, entry_type);
    
    /* Vérifier Execute Never pour Small Pages */
    uint32_t xn = entry & 0x1;   /* Bit XN dans le bit 0 */
    if (xn) {
        KERROR("check_page_permissions: Execute Never bit set for address 0x%08X\n", vaddr);
        return -1;
    }
    
    /* Vérifier que l'utilisateur peut accéder */
    if (ap == 0) {
        KERROR("check_page_permissions: No user access for address 0x%08X\n", vaddr);
        return -1;
    }
    
    KINFO("check_page_permissions: Address 0x%08X is properly mapped and executable (AP=%u, XN=%u)\n", 
          vaddr, ap, xn);
    return 0;
}

uint32_t get_current_ttrb0(void){
    uint32_t current_ttbr0;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r" (current_ttbr0));
    return current_ttbr0;
}

/**
 * Nouvelles fonctions utilitaires pour split TTBR
 */

/**
 * get_address_space_info - Obtient les informations sur l'espace d'adressage actuel
 */
void get_address_space_info(void)
{
    uint32_t ttbr0, ttbr1, ttbcr, contextidr;
    
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 1" : "=r"(contextidr));
    
    uint32_t n = ttbcr_get_n(ttbcr);
    uint32_t asid = contextidr_get_asid(contextidr);
    uint32_t split_boundary = get_split_boundary();
    
    KDEBUG("=== ADDRESS SPACE INFO ===\n");
    KDEBUG("TTBR0 (user):     0x%08X\n", ttbr0);
    KDEBUG("TTBR1 (kernel):   0x%08X\n", ttbr1);
    KDEBUG("TTBCR:            0x%08X\n", ttbcr);
    KDEBUG("  N field:        %u (%s split)\n", n, get_ttbcr_n_name(n));
    KDEBUG("  Split boundary: 0x%08X\n", split_boundary);
    KDEBUG("  PD0:            %s\n", ttbcr_get_pd0(ttbcr) ? "disabled" : "enabled");
    KDEBUG("  PD1:            %s\n", ttbcr_get_pd1(ttbcr) ? "disabled" : "enabled");
    KDEBUG("CONTEXTIDR:       0x%08X\n", contextidr);
    KDEBUG("  ASID:           %u\n", asid);
    KDEBUG("  PROCID:         %u\n", contextidr_get_procid(contextidr));
    KDEBUG("==========================\n");
}

/**
 * validate_split_ttbr_config - Valide la configuration split TTBR
 */
bool validate_split_ttbr_config(void)
{
    uint32_t ttbr0, ttbr1, ttbcr;
    bool valid = true;
    
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    
    KDEBUG("validate_split_ttbr_config: Validating configuration...\n");
    
    /* Vérifier l'alignement TTBR0 */
    if (ttbr0 & 0x3FFF) {
        KERROR("validate_split_ttbr_config: TTBR0 not 16KB aligned: 0x%08X\n", ttbr0);
        valid = false;
    }
    
    /* Vérifier l'alignement TTBR1 */
    if (ttbr1 & 0x3FFF) {
        KERROR("validate_split_ttbr_config: TTBR1 not 16KB aligned: 0x%08X\n", ttbr1);
        valid = false;
    }
    
    /* Vérifier que TTBCR.N est valide */
    uint32_t n = ttbcr_get_n(ttbcr);
    if (n > 3) {
        KERROR("validate_split_ttbr_config: Invalid TTBCR.N value: %u\n", n);
        valid = false;
    }
    
    /* Vérifier que les page directories sont différents */
    if (ttbr0 == ttbr1) {
        KWARN("validate_split_ttbr_config: TTBR0 and TTBR1 point to same address\n");
    }
    
    if (valid) {
        KDEBUG("validate_split_ttbr_config: Configuration is valid\n");
    } else {
        KERROR("validate_split_ttbr_config: Configuration has errors\n");
    }
    
    return valid;
}

/**
 * flush_tlb_for_asid - Flush TLB pour un ASID spécifique
 */
void flush_tlb_for_asid(uint32_t asid)
{
    if (asid > MAX_ASID) {
        KERROR("flush_tlb_for_asid: Invalid ASID %u\n", asid);
        return;
    }
    
    KDEBUG("flush_tlb_for_asid: Flushing TLB for ASID %u\n", asid);
    
    tlb_flush_by_asid(asid);
    
    KDEBUG("flush_tlb_for_asid: TLB flush completed for ASID %u\n", asid);
}

/**
 * get_vm_space_stats - Obtient les statistiques d'un VM space
 */
void get_vm_space_stats(vm_space_t* vm)
{
    uint32_t vma_count = 0;
    uint32_t total_size = 0;
    vma_t* vma;
    
    if (!vm) {
        KERROR("get_vm_space_stats: NULL vm space\n");
        return;
    }
    
    KDEBUG("=== VM SPACE STATS (ASID %u) ===\n", vm->asid);
    KDEBUG("Page directory:   0x%08X\n", (uint32_t)vm->pgdir);
    KDEBUG("Heap range:       0x%08X - 0x%08X\n", vm->heap_start, vm->heap_end);
    KDEBUG("Stack start:      0x%08X\n", vm->stack_start);
    
    /* Compter les VMAs */
    vma = vm->vma_list;
    while (vma) {
        uint32_t vma_size = vma->end - vma->start;
        total_size += vma_size;
        vma_count++;
        
        KDEBUG("VMA %u: 0x%08X - 0x%08X (%u KB) flags=0x%X\n", 
               vma_count, vma->start, vma->end, vma_size / 1024, vma->flags);
        
        vma = vma->next;
    }
    
    KDEBUG("Total VMAs:       %u\n", vma_count);
    KDEBUG("Total mapped:     %u KB\n", total_size / 1024);
    KDEBUG("================================\n");
}

/**
 * test_temp_mapping - Test la fonctionnalité de mapping temporaire
 */
bool test_temp_mapping(void)
{
    void* test_page;
    uint32_t temp_vaddr;
    volatile uint32_t* test_ptr;
    bool success = true;
    
    KDEBUG("test_temp_mapping: Starting temp mapping test...\n");
    
    /* Allouer une page de test */
    test_page = allocate_physical_page();
    if (!test_page) {
        KERROR("test_temp_mapping: Failed to allocate test page\n");
        return false;
    }
    
    KDEBUG("test_temp_mapping: Allocated test page at 0x%08X\n", (uint32_t)test_page);
    
    /* Mapper temporairement */
    temp_vaddr = map_temp_page((uint32_t)test_page);
    if (temp_vaddr == 0) {
        KERROR("test_temp_mapping: Failed to map temp page\n");
        free_physical_page(test_page);
        return false;
    }
    
    KDEBUG("test_temp_mapping: Temp mapped to 0x%08X\n", temp_vaddr);
    
    /* Tester l'accès */
    test_ptr = (volatile uint32_t*)temp_vaddr;
    
    /* Test d'écriture */
    *test_ptr = 0xDEADBEEF;
    if (*test_ptr != 0xDEADBEEF) {
        KERROR("test_temp_mapping: Write test failed\n");
        success = false;
    }
    
    /* Test de lecture */
    *test_ptr = 0x12345678;
    if (*test_ptr != 0x12345678) {
        KERROR("test_temp_mapping: Read test failed\n");
        success = false;
    }
    
    /* Unmapper */
    unmap_temp_page((void*)temp_vaddr);
    
    /* Libérer la page */
    free_physical_page(test_page);
    
    if (success) {
        KDEBUG("test_temp_mapping: Test passed ✓\n");
    } else {
        KERROR("test_temp_mapping: Test failed ✗\n");
    }
    
    return success;
}
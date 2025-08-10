/* kernel/memory/memory_detect.c - Adapte pour machine virt */
#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/debug_print.h>
#include <kernel/kernel.h>

/* DTB structures */
struct fdt_header {
    uint32_t magic;           /* 0xd00dfeed */
    uint32_t totalsize;       
    uint32_t off_dt_struct;   
    uint32_t off_dt_strings;  
    uint32_t off_mem_rsvmap;  
    uint32_t version;         
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

typedef struct {
    uint32_t cache_info;
    uint32_t tlb_info;
    uint32_t memory_model;
    uint32_t debug_features;
} cpu_memory_info_t;

/* Variable globale pour stocker l'adresse DTB */
extern uint32_t dtb_address;

/* Fonctions de detection */
static uint32_t detect_memory_from_dtb(void* dtb_ptr);
static cpu_memory_info_t get_cpu_memory_info(void);
static void print_cpu_memory_features(void);
static uint32_t detect_memory_intelligent(void);
static uint32_t probe_memory_range(uint32_t start, uint32_t end);
static bool test_memory_block(uint32_t addr, uint32_t size);

/* Stub pour compilation si necessaire */
void init_memory_detection(void)
{
    kprintf("[DEBUG] Memory detection initialized for machine virt\n");
}

/* Fonction principale exportee */
uint32_t detect_memory(void)
{
    kprintf("[INFO] Starting memory detection for machine virt...\n");
    
    /* 1. Afficher les informations CPU Cortex-A15 */
    print_cpu_memory_features();
    
    /* 2. Essayer la detection DTB */
    void* dtb = (void*)dtb_address;
    if (dtb && dtb != (void*)0) {
        uint32_t dtb_memory = detect_memory_from_dtb(dtb);
        if (dtb_memory > 0) {
            kprintf("[INFO] Memory from DTB: %d MB\n", dtb_memory / (1024*1024));
            return dtb_memory;
        }
    }
    
    /* 3. Detection intelligente par sondage */
    uint32_t detected = detect_memory_intelligent();
    kprintf("[INFO] Total detected memory: %d MB\n", detected / (1024*1024));
    
    return detected;
}

/* Implementations des fonctions statiques */
static uint32_t detect_memory_from_dtb(void* dtb_ptr)
{
    if (!dtb_ptr) {
        kprintf("[WARN] No DTB provided\n");
        return 0;
    }
    
    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    
    /* Verifier la signature DTB */
    if (__builtin_bswap32(fdt->magic) != 0xd00dfeed) {
        kprintf("[DEBUG] Invalid DTB magic: 0x%08x\n", fdt->magic);
        return 0;
    }
    
    kprintf("[INFO] Valid DTB found at %p\n", dtb_ptr);
    kprintf("[INFO] DTB size: %d bytes\n", __builtin_bswap32(fdt->totalsize));
    
    /* Pour machine virt, utiliser la taille definie dans kernel.h */
    /* TODO: Parser completement le DTB */
    return VIRT_RAM_SIZE; /* Defini dans kernel.h comme 4GB */
}

static cpu_memory_info_t get_cpu_memory_info(void)
{
    cpu_memory_info_t info;
    
    /* Cache Type Register */
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 1" : "=r"(info.cache_info));
    
    /* TLB Type Register */
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 3" : "=r"(info.tlb_info));
    
    /* Memory Model Feature Register 0 */
    __asm__ volatile("mrc p15, 0, %0, c0, c1, 4" : "=r"(info.memory_model));
    
    /* Debug Feature Register 0 */
    __asm__ volatile("mrc p15, 0, %0, c0, c1, 2" : "=r"(info.debug_features));
    
    return info;
}

static void print_cpu_memory_features(void)
{
    cpu_memory_info_t info = get_cpu_memory_info();
    
    kprintf("=== Cortex-A15 Memory Features ===\n");
    kprintf("Cache Info:     0x%08x\n", info.cache_info);
    kprintf("TLB Info:       0x%08x\n", info.tlb_info);
    kprintf("Memory Model:   0x%08x\n", info.memory_model);
    kprintf("Debug Features: 0x%08x\n", info.debug_features);
    
    /* Decoder les informations cache Cortex-A15 */
    uint32_t icache_line = 4 << ((info.cache_info >> 0) & 0xF);
    uint32_t dcache_line = 4 << ((info.cache_info >> 16) & 0xF);
    
    kprintf("I-Cache line:   %d bytes\n", icache_line);
    kprintf("D-Cache line:   %d bytes\n", dcache_line);
    
    /* Informations specifiques Cortex-A15 */
    //kprintf("L2 Cache line:  64 bytes (Cortex-A15)\n");
    //kprintf("Virtual addr:   40-bit (Large Physical Address)\n");
}

static uint32_t detect_memory_intelligent(void)
{
    kprintf("[INFO] Intelligent memory detection for machine virt...\n");
    
    /* Zones memoire pour machine virt - tester de facon progressive */
    struct memory_range {
        uint32_t start;
        uint32_t size_mb;
        const char* name;
    } ranges[] = {
        { VIRT_RAM_START, 1024, "QEMU Virt (1GB)" },    /* Commencer par 1GB */
        { VIRT_RAM_START, 2048, "QEMU Virt (2GB)" },    /* Puis 2GB */
        { VIRT_RAM_START, 4096, "QEMU Virt (4GB)" },    /* Enfin 4GB */
    };
    
    int i;
    uint32_t max_detected = 0;
    
    for (i = 0; i < 3; i++) {
        uint32_t end_addr = ranges[i].start + (ranges[i].size_mb * 1024 * 1024);
        
        kprintf("[DEBUG] Testing %s range: 0x%08X-0x%08X (%u MB)\n",
                ranges[i].name, ranges[i].start, end_addr, ranges[i].size_mb);
        
        uint32_t detected = probe_memory_range(ranges[i].start, end_addr);
        
        if (detected > max_detected) {
            max_detected = detected;
            kprintf("[INFO] Found %d MB in %s range\n", 
                    detected / (1024*1024), ranges[i].name);
            
            /* Si on a detecte moins que la taille theorique, pas la peine de continuer */
            if (detected < ranges[i].size_mb * 1024 * 1024) {
                kprintf("[INFO] Memory appears limited to %d MB, stopping detection\n", 
                        detected / (1024*1024));
                break;
            }
        } else {
            /* Pas de gain, arreter */
            kprintf("[DEBUG] No additional memory found, stopping at %d MB\n", 
                    max_detected / (1024*1024));
            break;
        }
    }
    
    if (max_detected == 0) {
        kprintf("[WARN] No memory detected, using fallback\n");
        max_detected = 1024 * 1024 * 1024; /* 1GB fallback */
    }
    
    return max_detected;
}

static uint32_t probe_memory_range(uint32_t start, uint32_t end)
{
    uint32_t total_size = 0;
    uint32_t addr;
    
    kprintf("[DEBUG] Probing memory from 0x%08X to 0x%08X\n", start, end);
    
    /* Commencer juste apres le kernel pour eviter de corrompre le code en cours */
    uint32_t safe_start = MAX(start, KERNEL_END + 0x100000); /* 1MB apres le kernel */
    
    /* Tester par blocs de 16MB mais s'arreter AVANT de depasser */
    for (addr = safe_start; addr + 0x1000000 <= end; addr += 0x1000000) {
        /* Verifier que le test ne depassera pas la limite */
        if (addr + 0x100000 > end) {
            //kprintf("[DEBUG] Block at 0x%08X: SKIPPED - would exceed limit 0x%08X\n", addr, end);
            break;
        }
        
        if (test_memory_block(addr, 0x100000)) { /* Test sur 1MB seulement */
            total_size += 0x1000000; /* Mais compte 16MB si succes */
            //kprintf("[DEBUG] Block at 0x%08X: OK\n", addr);
        } else {
            //kprintf("[DEBUG] Block at 0x%08X: FAILED - stopping\n", addr);
            break; /* Arreter au premier echec */
        }
    }
    
    /* Ajouter la taille de depart (kernel + zone de securite) */
    if (total_size > 0) {
        total_size += (safe_start - start);
    }
    
    kprintf("[DEBUG] Total detected in range: %u MB\n", total_size / (1024*1024));
    return total_size;
}

static bool test_memory_block(uint32_t addr, uint32_t size)
{
    /* eviter la zone kernel pour machine virt - utiliser les constantes */
    if (addr >= KERNEL_START && addr < KERNEL_END) {
        return true; /* Supposer que la zone kernel est valide */
    }
    
    /* eviter aussi une zone tampon autour du kernel */
    if (addr >= KERNEL_START - 0x100000 && addr < KERNEL_END + 0x100000) {
        return true; /* Zone tampon de 1MB autour du kernel */
    }
    
    /* Ne tester que quelques adresses dans le bloc, pas tout le bloc */
    uint32_t test_offsets[] = {0, size/4, size/2, 3*size/4};
    int i;
    
    for (i = 0; i < 4; i++) {
        uint32_t test_addr = addr + test_offsets[i];
        volatile uint32_t* ptr = (volatile uint32_t*)test_addr;
        uint32_t original;
        
        /* Protection contre les exceptions - test simple */
        __asm__ volatile("" ::: "memory");
        
        /* Test de lecture simple d'abord */
        original = *ptr;
        
        /* Test d'ecriture/lecture */
        *ptr = 0x12345678;
        if (*ptr != 0x12345678) {
            return false;
        }
        
        *ptr = 0x87654321;
        if (*ptr != 0x87654321) {
            return false;
        }
        
        /* Restaurer la valeur originale */
        *ptr = original;
    }
    
    return true;
}
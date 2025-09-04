/* kernel/memory/memory_detect.c - Adapte pour machine virt */
#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/debug_print.h>
#include <kernel/kernel.h>



static inline uint32_t fdt32_to_cpu(uint32_t x) {
    return __builtin_bswap32(x);
}

/* Variable globale pour stocker l'adresse DTB */
extern uint32_t dtb_address;

uint32_t kernel_memory_size = 0;

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

bool fdt_node_matches(const char* node_name, const char* prefix) {
    size_t len = strlen(prefix);
    return (strncmp(node_name, prefix, len) == 0 &&
            (node_name[len] == '@' || node_name[len] == '\0'));
}

uint32_t get_kernel_memory_size(void){
    return kernel_memory_size;
}

void* fdt_find_node_by_name(void* dtb_ptr, const char* node_name) {
    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    uint8_t* struct_block = (uint8_t*)dtb_ptr + fdt32_to_cpu(fdt->off_dt_struct);

    uint32_t* token = (uint32_t*)struct_block;

    while (1) {
        uint32_t tag = fdt32_to_cpu(*token++);
        switch (tag) {
            case FDT_BEGIN_NODE: {
                const char* name = (const char*)token;
                size_t len = strlen(name);
                KDEBUG("fdt_find_node_by_name: node %s\n", name);
                if (fdt_node_matches(name, node_name)) {
                    KDEBUG("fdt_find_node_by_name: node %s\n", name);
                    return (void*)(token - 1);  // retour sur le tag FDT_BEGIN_NODE
                }
                token += (len + 4) / 4;
                break;
            }
            case FDT_PROP: {
                uint32_t len = fdt32_to_cpu(*token++);
                token++;  // skip name_offset
                token += (len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
                break;
            case FDT_NOP:
                break;
            case FDT_END:
                return NULL;
            default:
                return NULL;
        }
    }
}

bool fdt_device_present(void* dtb_ptr, const char* partial_name) {
    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    uint8_t* struct_block = (uint8_t*)dtb_ptr + fdt32_to_cpu(fdt->off_dt_struct);

    uint32_t* token = (uint32_t*)struct_block;

    while (1) {
        uint32_t tag = fdt32_to_cpu(*token++);
        switch (tag) {
            case FDT_BEGIN_NODE: {
                const char* name = (const char*)token;
                size_t len = strlen(name);
                if (strstr(name, partial_name) != NULL) {
                    return true;
                }
                token += (len + 4) / 4;
                break;
            }
            case FDT_PROP: {
                uint32_t len = fdt32_to_cpu(*token++);
                token++;  // name_off
                token += (len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
                break;
            case FDT_NOP:
                break;
            case FDT_END:
                return false;
            default:
                return false;
        }
    }
}

void* fdt_get_property(void* dtb_ptr, void* node_ptr, const char* property_name, uint32_t* out_len) {
    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    uint8_t* strings_block = (uint8_t*)dtb_ptr + __builtin_bswap32(fdt->off_dt_strings);

    uint32_t* token = (uint32_t*)node_ptr;
    token++;  // Skip FDT_BEGIN_NODE tag
    const char* node_name = (const char*)token;
    token += (strlen(node_name) + 4) / 4;

    while (1) {
        uint32_t tag = __builtin_bswap32(*token++);
        switch (tag) {
            case FDT_PROP: {
                uint32_t len = __builtin_bswap32(*token++);
                uint32_t name_off = __builtin_bswap32(*token++);

                const char* name = (const char*)(strings_block + name_off);
                if (strcmp(name, property_name) == 0) {
                    if (out_len) *out_len = len;
                    return (void*)token;
                }

                token += (len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
                return NULL;
            case FDT_NOP:
                break;
            case FDT_END:
                return NULL;
            default:
                return NULL;
        }
    }
}



/* Fonction principale exportee */
uint32_t detect_memory(void)
{
    if( kernel_memory_size )
        return kernel_memory_size ;
    
    kprintf("[INFO] Starting memory detection for machine virt...\n");
    
    /* 1. Afficher les informations CPU Cortex-A15 */
    print_cpu_memory_features();

    //dtb_address = 0x40000000;
    
    /* 2. Essayer la detection DTB */
    void* dtb = (void*)dtb_address;
    if (dtb && dtb != (void*)0) {
        uint32_t dtb_memory = detect_memory_from_dtb(dtb);
        if (dtb_memory > 0) {
            kprintf("[INFO] Memory from DTB: %d MB\n", dtb_memory / (1024*1024));
            kernel_memory_size = dtb_memory ;
            return dtb_memory;
        }
    }
    
    /* 3. Detection intelligente par sondage */
    uint32_t detected = detect_memory_intelligent();
    kprintf("[INFO] Total detected memory: %d MB\n", detected / (1024*1024));
    kernel_memory_size = detected;
    return detected;
}

/* Implementations des fonctions statiques */
static uint32_t detect_memory_from_dtb(void* dtb_ptr)
{
    if (!dtb_ptr) {
        kprintf("[WARN] No DTB provided\n");
        return 0;
    }

    uint32_t *addr = (uint32_t*)dtb_ptr;
    uint32_t content = *addr ;
 
    kprintf("[INFO] Trying detection from DTB at %p - 0x%08X\n", dtb_ptr, content);

    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    
    /* Verifier la signature DTB */
    if (__builtin_bswap32(fdt->magic) != 0xd00dfeed) {
        kprintf("[DEBUG] Invalid DTB magic: 0x%08x\n", fdt->magic);
        return 0;
    }
    
    kprintf("[INFO] Valid DTB found at %p\n", dtb_ptr);
    kprintf("[INFO] DTB size: %ld bytes\n", __builtin_bswap32(fdt->totalsize));

    void* node = fdt_find_node_by_name(dtb_ptr, "memory");
    if (node) {
        uint32_t len;
        uint32_t* reg = (uint32_t*)fdt_get_property(dtb_ptr, node, "reg", &len);
        if (reg) {
            uint64_t base64 = ((uint64_t)__builtin_bswap32(reg[0]) << 32) | __builtin_bswap32(reg[1]);
            uint64_t size64 = ((uint64_t)__builtin_bswap32(reg[2]) << 32) | __builtin_bswap32(reg[3]);

            if ((base64 >> 32) != 0 || (size64 >> 32) != 0) {
                kprintf("[ERROR] 64-bit memory range not supported on ARMv7: base=0x%llx, size=0x%llx\n", base64, size64);
                return -1;
            }

            uint32_t base = (uint32_t)(base64 & 0xFFFFFFFF);
            uint32_t size = (uint32_t)(size64 & 0xFFFFFFFF);

            kprintf("[INFO] Memory region: base=0x%08X, size=0x%08X\n", base, size);

            return size;
            
        }
    }
    
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
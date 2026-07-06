/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/memory/memory_detect.c
 * Layer: ARM32 / platform memory detection
 *
 * Responsibilities:
 * - Detect the physical RAM size exposed to the ARM32 kernel.
 * - Prefer the boot DTB memory node and keep conservative probing as fallback.
 *
 * Notes:
 * - CPU feature reads are ARM32-specific CP15 queries and stay local here.
 */

#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/address_space.h>
#include <kernel/debug_print.h>
#include <kernel/fdt.h>
#include <asm/arm.h>

uint32_t kernel_memory_size = 0;

typedef struct {
    uint32_t cache_info;
    uint32_t tlb_info;
    uint32_t memory_model;
    uint32_t debug_features;
} cpu_memory_info_t;

/* Fonctions de detection */
static uint32_t detect_memory_from_dtb(void* dtb_ptr);
static cpu_memory_info_t get_cpu_memory_info(void);
static void print_cpu_memory_features(void);
static uint32_t detect_memory_intelligent(void);
static uint32_t probe_memory_range(paddr_t start, paddr_t end);
static bool test_memory_block(paddr_t addr, uint32_t size);

/* Stub pour compilation si necessaire */
void init_memory_detection(void)
{
    KDEBUG("Memory detection initialized for %s\n", arch_platform_name());
}

uint32_t get_kernel_memory_size(void){
    return kernel_memory_size;
}

/* Fonction principale exportee */
uint32_t detect_memory(void)
{
    if( kernel_memory_size )
        return kernel_memory_size ;
    
    KINFO("Starting memory detection for %s...\n", arch_platform_name());
    
    /* 1. Print ARM32 CP15 memory/cache feature registers. */
    print_cpu_memory_features();

    //dtb_address = 0x40000000;
    
    /* 2. Essayer la detection DTB */
    void* dtb = (void*)dtb_address;
    if (dtb && dtb != (void*)0) {
        uint32_t dtb_memory = detect_memory_from_dtb(dtb);
        if (dtb_memory > 0) {
            KINFO("Memory from DTB: %d MB\n", dtb_memory / (1024*1024));
            kernel_memory_size = dtb_memory ;
            return dtb_memory;
        }
    }
    
    /* 3. Detection intelligente par sondage */
    uint32_t detected = detect_memory_intelligent();
    KINFO("Total detected memory: %d MB\n", detected / (1024*1024));
    kernel_memory_size = detected;
    return detected;
}

/* Implementations des fonctions statiques */
static uint32_t detect_memory_from_dtb(void* dtb_ptr)
{
    if (!dtb_ptr) {
        KWARN("No DTB provided\n");
        return 0;
    }

    uint32_t *addr = (uint32_t*)dtb_ptr;
    uint32_t content = *addr ;
 
    KINFO("Trying detection from DTB at %p - 0x%08X\n", dtb_ptr, content);

    struct fdt_header* fdt = (struct fdt_header*)dtb_ptr;
    
    /* Verifier la signature DTB */
    if (!fdt_check_header(dtb_ptr)) {
        KDEBUG("Invalid DTB magic: 0x%08x\n", fdt->magic);
        return 0;
    }
    
    KINFO("Valid DTB found at %p\n", dtb_ptr);
    KINFO("DTB size: %u bytes\n", fdt32_to_cpu(fdt->totalsize));

    void* node = fdt_find_node_by_name(dtb_ptr, "memory");
    if (node) {
        uint32_t len;
        uint32_t* reg = (uint32_t*)fdt_get_property(dtb_ptr, node, "reg", &len);
        if (reg) {
            uint64_t base64 = ((uint64_t)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
            uint64_t size64 = ((uint64_t)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);

            if ((base64 >> 32) != 0 || (size64 >> 32) != 0) {
                KERROR("64-bit memory range not supported on ARMv7: base=0x%llx, size=0x%llx\n", base64, size64);
                return -1;
            }

            paddr_t base = (paddr_t)(base64 & 0xFFFFFFFF);
            uint32_t size = (uint32_t)(size64 & 0xFFFFFFFF);

            KINFO("Memory region: base=0x%08X, size=0x%08X\n", base, size);

            return size;
            
        }
    }
    
    return 0;
}

static cpu_memory_info_t get_cpu_memory_info(void)
{
    cpu_memory_info_t info;
    
    /* Cache Type Register */
    info.cache_info = arm_read_ctr();
    
    /* TLB Type Register */
    info.tlb_info = arm_read_tlbtr();
    
    /* Memory Model Feature Register 0 */
    info.memory_model = arm_read_mmfr0();
    
    /* Debug Feature Register 0 */
    info.debug_features = arm_read_dfr0();
    
    return info;
}

static void print_cpu_memory_features(void)
{
    cpu_memory_info_t info = get_cpu_memory_info();
    
    KINFO("=== ARM32 Memory Features ===\n");
    KINFO("Cache Info:     0x%08x\n", info.cache_info);
    KINFO("TLB Info:       0x%08x\n", info.tlb_info);
    KINFO("Memory Model:   0x%08x\n", info.memory_model);
    KINFO("Debug Features: 0x%08x\n", info.debug_features);
    
    /* Decode cache line information reported by CLIDR/CCSIDR helpers. */
    uint32_t icache_line = 4 << ((info.cache_info >> 0) & 0xF);
    uint32_t dcache_line = 4 << ((info.cache_info >> 16) & 0xF);
    
    KINFO("I-Cache line:   %d bytes\n", icache_line);
    KINFO("D-Cache line:   %d bytes\n", dcache_line);
    
    /* Historical bring-up notes kept disabled until a per-CPU decoder exists. */
    //kprintf("L2 Cache line:  64 bytes (Cortex-A15)\n");
    //kprintf("Virtual addr:   40-bit (Large Physical Address)\n");
}

static uint32_t detect_memory_intelligent(void)
{
    KINFO("Intelligent memory detection for %s...\n", arch_platform_name());

    paddr_t ram_start = arch_platform_ram_start();
    uint32_t max_probe_mb = arch_platform_ram_probe_max_mb();
    uint32_t probe_mb = max_probe_mb < 1024u ? max_probe_mb : 1024u;
    uint32_t max_detected = 0;

    while (probe_mb > 0 && probe_mb <= max_probe_mb) {
        uint64_t probe_bytes = (uint64_t)probe_mb * 1024u * 1024u;
        uint64_t end64 = (uint64_t)ram_start + probe_bytes;
        paddr_t end_addr = end64 > 0xFFFFFFFFull ? (paddr_t)0xFFFFFFFFu : (paddr_t)end64;

        KDEBUG("Testing %s RAM range: 0x%08X-0x%08X (%u MB)\n",
                arch_platform_name(), ram_start, end_addr, probe_mb);

        uint32_t detected = probe_memory_range(ram_start, end_addr);

        if (detected > max_detected) {
            max_detected = detected;
            KINFO("Found %d MB in %s RAM range\n",
                    detected / (1024*1024), arch_platform_name());

            /* Si on a detecte moins que la taille theorique, pas la peine de continuer */
            if ((uint64_t)detected < probe_bytes) {
                KINFO("Memory appears limited to %d MB, stopping detection\n",
                        detected / (1024*1024));
                break;
            }
        } else {
            /* Pas de gain, arreter */
            KDEBUG("No additional memory found, stopping at %d MB\n", 
                    max_detected / (1024*1024));
            break;
        }

        if (probe_mb >= max_probe_mb)
            break;

        uint32_t next_probe_mb = probe_mb * 2u;
        if (next_probe_mb < probe_mb || next_probe_mb > max_probe_mb)
            next_probe_mb = max_probe_mb;
        probe_mb = next_probe_mb;
    }
    
    if (max_detected == 0) {
        KWARN("No memory detected, using fallback\n");
        max_detected = arch_platform_ram_fallback_size();
    }
    
    return max_detected;
}

static uint32_t probe_memory_range(paddr_t start, paddr_t end)
{
    uint32_t total_size = 0;
    paddr_t addr;
    
    KDEBUG("Probing memory from 0x%08X to 0x%08X\n", start, end);
    
    /* Commencer juste apres le kernel pour eviter de corrompre le code en cours */
    paddr_t safe_start = MAX(start, (paddr_t)KERNEL_END + 0x100000); /* 1MB apres le kernel */
    
    /* Tester par blocs de 16MB mais s'arreter AVANT de depasser */
    for (addr = safe_start; addr + 0x1000000 <= end; addr += 0x1000000) {
        /* Verifier que le test ne depassera pas la limite */
        if (addr + 0x100000 > end) {
            //KDEBUG("Block at 0x%08X: SKIPPED - would exceed limit 0x%08X\n", addr, end);
            break;
        }
        
        if (test_memory_block(addr, 0x100000)) { /* Test sur 1MB seulement */
            total_size += 0x1000000; /* Mais compte 16MB si succes */
            //KDEBUG("Block at 0x%08X: OK\n", addr);
        } else {
            //KDEBUG("Block at 0x%08X: FAILED - stopping\n", addr);
            break; /* Arreter au premier echec */
        }
    }
    
    /* Ajouter la taille de depart (kernel + zone de securite) */
    if (total_size > 0) {
        total_size += (safe_start - start);
    }
    
    KDEBUG("Total detected in range: %u MB\n", total_size / (1024*1024));
    return total_size;
}

static bool test_memory_block(paddr_t addr, uint32_t size)
{
    /* Avoid probing the live kernel mapping. */
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
        paddr_t test_addr = addr + test_offsets[i];
        volatile uint32_t* ptr = (volatile uint32_t*)(uintptr_t)test_addr;
        uint32_t original;
        
        /* Protection contre les exceptions - test simple */
        compiler_barrier();
        
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

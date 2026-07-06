/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kernel.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_H
#define _KERNEL_H

#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/fdt.h>
#include <asm/platform.h>
#include <asm/memory_layout.h>
#include <asm/user_layout.h>
#include <asm/arm.h>

#define USE_RAMFS 1

uint32_t get_kernel_memory_size(void);

/* === INFORMATIONS DU LINKER SCRIPT === */

/* Symboles exportes par le linker script pour machine virt */
extern uint32_t __start;           /* Debut du kernel */
extern uint32_t __end;             /* Fin du kernel */
extern uint32_t __kernel_start;    /* Alias pour __start */
extern uint32_t __kernel_end;      /* Alias pour __end */
extern uint32_t __kernel_size;     /* Taille du kernel */

/* Sections du kernel */
extern uint32_t __text_start;      /* Debut section .text */
extern uint32_t __text_end;        /* Fin section .text */
extern uint32_t __rodata_start;    /* Debut section .rodata */
extern uint32_t __rodata_end;      /* Fin section .rodata */
extern uint32_t __data_start;      /* Debut section .data */
extern uint32_t __data_end;        /* Fin section .data */
extern uint32_t __bss_start;       /* Debut section .bss */
extern uint32_t __bss_end;         /* Fin section .bss */

//extern uint32_t __mmu_tables_start;
//extern uint32_t __mmu_tables_end;
//extern uint32_t __mmu_size;

/* Pile et heap kernel */
extern uint32_t __stack_bottom;    /* Debut de la pile kernel */
extern uint32_t __stack_top;       /* Fin de la pile kernel */
extern uint32_t stack_bottom;      /* Alias */
extern uint32_t stack_top;         /* Alias */
extern uint32_t __heap_start;      /* Debut du heap kernel */
extern uint32_t __heap_end;        /* Fin du heap kernel */
extern uint32_t __heap_size;       /* Taille du heap kernel */
extern uint32_t __ram_start;       /* Debut RAM libre */
extern uint32_t __ram_end;         /* Fin RAM libre */
extern uint32_t __ram_size;        /* Taille RAM libre */
extern uint32_t __free_memory_start; /* Debut memoire libre */

extern uint32_t __stack_svc_top;

/* ========================================================================
 * MEMORY LAYOUT
 * ======================================================================== */
#define VIRT_RAM_SIZE           get_kernel_memory_size()
#define VIRT_RAM_END            (VIRT_RAM_START + VIRT_RAM_SIZE)

static inline bool phys_in_direct_map(paddr_t paddr)
{
    return paddr >= VIRT_RAM_START &&
           paddr < (VIRT_RAM_START + KERNEL_DIRECT_MAP_SIZE);
}

static inline bool virt_in_direct_map(vaddr_t vaddr)
{
    return vaddr >= KERNEL_DIRECT_MAP_BASE && vaddr < KERNEL_DIRECT_MAP_END;
}

static inline vaddr_t phys_to_virt(paddr_t paddr)
{
    return paddr + KERNEL_DIRECT_MAP_OFFSET;
}

static inline paddr_t virt_to_phys(vaddr_t vaddr)
{
    if (virt_in_direct_map(vaddr))
        return vaddr - KERNEL_DIRECT_MAP_OFFSET;

    /*
     * Compatibility for the boot identity window and current low kernel link
     * address.  Drivers and new allocator users should not rely on this path.
     */
    return vaddr;
}

/* ========================================================================
 * KERNEL SPACE (utilise les symboles du linker)
 * ======================================================================== */
#define KERNEL_START            ((vaddr_t)(uintptr_t)&__start)          /* Debut kernel */
#define KERNEL_END              ((vaddr_t)(uintptr_t)&__end)            /* Fin kernel */
#define KERNEL_SIZE             ((size_t)(uintptr_t)&__kernel_size)     /* Taille kernel */
#define KERNEL_BASE             KERNEL_START                  /* Alias compatibilite */

/* Sections kernel */
#define KERNEL_TEXT_START       ((vaddr_t)(uintptr_t)&__text_start)
#define KERNEL_TEXT_END         ((vaddr_t)(uintptr_t)&__text_end)
#define KERNEL_DATA_START       ((vaddr_t)(uintptr_t)&__data_start)
#define KERNEL_DATA_END         ((vaddr_t)(uintptr_t)&__data_end)
#define KERNEL_BSS_START        ((vaddr_t)(uintptr_t)&__bss_start)
#define KERNEL_BSS_END          ((vaddr_t)(uintptr_t)&__bss_end)

/* Stack kernel */
#define KERNEL_STACK_BOTTOM     ((vaddr_t)(uintptr_t)&__stack_bottom)
#define KERNEL_STACK_TOP        ((vaddr_t)(uintptr_t)&__stack_top)
#define KERNEL_STACK_SIZE       (KERNEL_STACK_TOP - KERNEL_STACK_BOTTOM)

/* Heap kernel (defini par le linker) */
#define KERNEL_HEAP_START       ((vaddr_t)(uintptr_t)&__heap_start)
#define KERNEL_HEAP_END         ((vaddr_t)(uintptr_t)&__heap_end)
#define KERNEL_HEAP_SIZE        ((size_t)(uintptr_t)&__heap_size)

/* RAM physique disponible (apres kernel et heap) */
#define PHYSICAL_RAM_START      ((paddr_t)(uintptr_t)&__ram_start)
#define PHYSICAL_RAM_END        ((paddr_t)(uintptr_t)&__ram_end)
#define PHYSICAL_RAM_SIZE       ((size_t)(uintptr_t)&__ram_size)
#define FREE_MEMORY_START       ((paddr_t)(uintptr_t)&__free_memory_start)

#define KERNEL_SVC_STACK_TOP    ((vaddr_t)(uintptr_t)&__stack_svc_top)

/* Aliases pour compatibilite */
#define HEAP_START              KERNEL_HEAP_START
#define HEAP_END                KERNEL_HEAP_END
#define HEAP_SIZE               KERNEL_HEAP_SIZE
#define RAM_START               PHYSICAL_RAM_START
#define RAM_END                 PHYSICAL_RAM_END
#define RAM_SIZE                PHYSICAL_RAM_SIZE

/* ========================================================================
 * USER SPACE
 * ======================================================================== */

/*
 * Compatibility aliases for the user virtual layout.  The concrete addresses
 * are supplied by the active architecture backend.
 */
#define USER_SPACE_START         ARCH_USER_SPACE_START
#define USER_STACK_TOP           ARCH_USER_STACK_TOP
#define USER_STACK_SIZE          ARCH_USER_STACK_SIZE
#define USER_STACK_BOTTOM        ARCH_USER_STACK_BOTTOM
#define USER_HEAP_START          ARCH_USER_HEAP_START
#define USER_SHM_START           ARCH_USER_SHM_START
#define USER_SHM_END             ARCH_USER_SHM_END
#define USER_HEAP_END            ARCH_USER_HEAP_END
#define USER_SPACE_END           ARCH_USER_SPACE_END
#define USER_HEAP_MAX_SIZE       (USER_HEAP_END - USER_HEAP_START)

#define USER_SIGNAL_REGION_START ARCH_USER_SIGNAL_REGION_START
#define USER_SIGNAL_REGION_END   ARCH_USER_SIGNAL_REGION_END
#define USER_SIGNAL_REGION_SIZE  ARCH_USER_SIGNAL_REGION_SIZE

/* ========================================================================
 * SIGNAL STACK - UTILISE LA ZONE LIBRE APReS USER_STACK_TOP
 * ======================================================================== */

/* Signal stack dans la zone libre entre user space et kernel */
#define DEFAULT_SIGNAL_STACK_SIZE   (16*1024u)                 /* 16KB par defaut */
#define MAX_SIGNAL_STACK_SIZE       (1024*1024u)               /* 1MB maximum */

/* Base pour signal stack (dans la zone libre de 16MB) */
#define SIGNAL_STACK_BASE_DEFAULT   (USER_SIGNAL_REGION_START + DEFAULT_SIGNAL_STACK_SIZE)

/* ========================================================================
 * MACROS UTILITAIRES
 * ======================================================================== */

/* Alignement de pages */
#define ALIGN_UP(x, align)      (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align)    ((x) & ~((align) - 1))

#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & (PAGE_SIZE - 1)) == 0)

/* Verifications d'adresses pour machine virt */
//#define IS_KERNEL_ADDR(addr)    ((addr) >= KERNEL_START && (addr) < VIRT_RAM_END)
//#define IS_USER_ADDR(addr)      ((addr) >= USER_SPACE_START && (addr) < USER_SPACE_END)
#define IS_DEVICE_ADDR(addr)    ((addr) >= DEVICE_START && (addr) < DEVICE_END)
#define IS_VALID_RAM(addr)      ((addr) >= VIRT_RAM_START && (addr) < VIRT_RAM_END)
#define IS_VIRTIO_ADDR(addr)    ((addr) >= VIRT_VIRTIO_BASE && (addr) < (VIRT_VIRTIO_BASE + VIRT_VIRTIO_SIZE * 8))
#define IS_GIC_ADDR(addr)       ((addr) >= VIRT_GIC_DIST_BASE && (addr) < (VIRT_GIC_VCPU_BASE + VIRT_GIC_VCPU_SIZE))

/* Pages */
#define ADDR_TO_PAGE(addr)      ((addr) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(page)      ((page) << PAGE_SHIFT)

/* Utilitaires */
#define MIN(a, b)               ((a) < (b) ? (a) : (b))
#define MAX(a, b)               ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))

/* Implemented in boot.S */
extern void PUT32(unsigned int, unsigned int);
extern unsigned int GET32(unsigned int);
extern void PUT8(unsigned int, unsigned int);  /* Compatible avec mmio.h */
extern unsigned int GET8(unsigned int);        /* Compatible avec mmio.h */
extern void PUT16(unsigned int, unsigned int); /* Compatible avec mmio.h */
extern unsigned int GET16(unsigned int);       /* Compatible avec mmio.h */


typedef struct {
    uint32_t cache_info;
    uint32_t tlb_info;
    uint32_t memory_model;
    uint32_t debug_features;
} cpu_memory_info_t;

/* === FONCTIONS KERNEL === */

/* Panic et debug */
void panic(const char* message) __attribute__((noreturn));

/* Initialisation precoce */
void init_early_uart(void);
uint32_t detect_memory(void);

/* Informations du kernel */
static inline vaddr_t get_kernel_start(void) { return KERNEL_START; }
static inline vaddr_t get_kernel_end(void) { return KERNEL_END; }
static inline size_t get_kernel_size(void) { return KERNEL_SIZE; }

/* Informations des sections */
static inline vaddr_t get_text_start(void) { return KERNEL_TEXT_START; }
static inline vaddr_t get_text_end(void) { return KERNEL_TEXT_END; }
static inline size_t get_text_size(void) {
    return (size_t)(KERNEL_TEXT_END - KERNEL_TEXT_START);
}

static inline vaddr_t get_data_start(void) { return KERNEL_DATA_START; }
static inline vaddr_t get_data_end(void) { return KERNEL_DATA_END; }
static inline size_t get_data_size(void) {
    return (size_t)(KERNEL_DATA_END - KERNEL_DATA_START);
}

static inline vaddr_t get_bss_start(void) { return KERNEL_BSS_START; }
static inline vaddr_t get_bss_end(void) { return KERNEL_BSS_END; }
static inline size_t get_bss_size(void) {
    return (size_t)(KERNEL_BSS_END - KERNEL_BSS_START);
}

static inline vaddr_t get_heap_start(void) { return KERNEL_HEAP_START; }

/* Fonction de debug pour afficher le layout memoire */
void print_kernel_layout(void);

/* Supprimer les declarations en conflit avec mmio.h */
/* GIC (Generic Interrupt Controller) */
void gic_init(void);
void gic_enable_irq_kernel(uint32_t irq);  /* Renamed pour eviter conflit */
void gic_disable_irq(uint32_t irq);
uint32_t gic_get_active_irq(void);
void gic_ack_irq_kernel(uint32_t irq);     /* Renamed pour eviter conflit */

/* ARM Generic Timer */
void timer_init(void);
uint64_t timer_get_count(void);
void timer_set_compare(uint64_t compare);
uint32_t timer_get_frequency(void);

/* VirtIO support */
bool virtio_probe_device(uint32_t device_id);
void virtio_init(void);

/* Device Tree support */
void* get_dtb_address(void);
bool parse_device_tree(void);
void print_cpu_mode(void);




/* === VeRIFICATIONS DE COMPATIBILITe === */

/* Verifier que les adresses sont coherentes */
#if VIRT_RAM_START != 0x40000000u
#error "VIRT_RAM_START must be 0x40000000 for machine virt"
#endif

#if PAGE_SIZE != 4096
#error "PAGE_SIZE must be 4096 for ARM32"
#endif

/* === ATTRIBUTS COMPILATEUR === */

/* Sections speciales */
#define __init_code             __attribute__((section(".text.init")))
#define __init_data             __attribute__((section(".data.init")))
#define __kernel_data           __attribute__((section(".data.kernel")))

/* Alignement ARM32 */
#define __aligned_4             __attribute__((aligned(4)))
#define __aligned_8             __attribute__((aligned(8)))
#define __aligned_page          __attribute__((aligned(PAGE_SIZE)))
#define __cache_aligned         __attribute__((aligned(CACHE_LINE_SIZE)))

/* Optimisations */
#define __always_inline         __attribute__((always_inline))
#define __noinline              __attribute__((noinline))
#define __pure                  __attribute__((pure))
#define __const                 __attribute__((const))

/* CPU feature aliases kept for compatibility while arch headers take over. */
#define CORTEX_A15_FEATURES     ARM_CORTEX_A15_FEATURES
#define HAS_NEON                ARM_HAS_NEON
#define HAS_VFP                 ARM_HAS_VFP
#define HAS_GENERIC_TIMER       ARM_HAS_GENERIC_TIMER
#define HAS_LARGE_PHYS_ADDR     ARM_HAS_LARGE_PHYS_ADDR

#define STDIN_FILENO            0
#define STDOUT_FILENO           1
#define STDERR_FILENO           2


/* ARM privileged register/cache helpers are exposed through <asm/arm.h>. */

#define offsetof(type, member) ((size_t)&((type*)0)->member)

//extern const uint32_t TASK_CONTEXT_OFF;

#endif /* _KERNEL_H */

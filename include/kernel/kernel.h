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
#include <kernel/compiler.h>
#include <kernel/stddef.h>
#include <kernel/fd.h>
#include <kernel/linker.h>
#include <asm/cpu_features.h>
#include <asm/platform.h>
#include <asm/memory_layout.h>
#include <asm/user_layout.h>

#define USE_RAMFS 1

uint32_t get_kernel_memory_size(void);

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

/* Verifications d'adresses */
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
/* CPU feature aliases kept for compatibility while arch headers take over. */
#define CORTEX_A15_FEATURES     ARCH_CORTEX_A15_FEATURES
#define HAS_NEON                ARCH_HAS_NEON
#define HAS_VFP                 ARCH_HAS_VFP
#define HAS_GENERIC_TIMER       ARCH_HAS_GENERIC_TIMER
#define HAS_LARGE_PHYS_ADDR     ARCH_HAS_LARGE_PHYS_ADDR

/* ARM privileged register/cache helpers are exposed through <asm/arm.h>. */

//extern const uint32_t TASK_CONTEXT_OFF;

#endif /* _KERNEL_H */

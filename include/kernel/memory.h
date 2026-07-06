/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/memory.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_MEMORY_H
#define _KERNEL_MEMORY_H

#include <kernel/arch_mmu.h>
#include <kernel/types.h>
#include <kernel/user_layout.h>

typedef struct {
    uint32_t* bitmap;
    uint32_t total_pages;
    uint32_t free_pages;
    paddr_t start_addr;
    uint32_t bitmap_pages;  /* Nombre de pages utilisees par le bitmap */
    uint32_t pages_allocated;
    uint32_t pages_freed;
} __attribute__((aligned(4))) physical_allocator_t;

/* Virtual Memory Area */
typedef struct vma {
    vaddr_t start;         /* 4 bytes */
    vaddr_t end;           /* 4 bytes */
    uint32_t flags;        /* 4 bytes */
    uint32_t shm_id;       /* ID SHM si VMA_SHARED */
    struct vma* next;      /* 4 bytes */
    uint32_t padding2;     /* 4 bytes - pour compléter 8 */
} __attribute__((aligned(8))) vma_t;
/* Taille: 24 bytes - alignée sur 8 OK */

typedef struct vm_space {
    pgdir_t pgdir;         /* TTBR0 physical base, pointer-shaped legacy ABI */
    pgdir_t pgdir_alloc;   /* Raw physical allocation base to free */
    vma_t* vma_list;       /* 4 bytes */
    vaddr_t heap_start;    /* 4 bytes */
    vaddr_t heap_end;      /* 4 bytes */
    vaddr_t brk;           /* 4 bytes */
    vaddr_t stack_start;   /* 4 bytes */
    uint32_t asid;         /* 4 bytes - NOUVEAU: ASID du processus */
    uint32_t padding;      /* 4 bytes pour aligner sur 8 */
} __attribute__((aligned(8))) vm_space_t;

/*
 * Anonymous mmap area.
 *
 * The historical ArmOS layout leaves 0x34000000..0x37000000 unused between
 * shared-memory mappings and the user stack. Keep mmap there so anonymous
 * mappings cannot collide with brk(), SHM, or stack growth.
 */
#define USER_MMAP_START USER_SHM_END
#define USER_MMAP_END   USER_STACK_BOTTOM

/*
 * Generic virtual-address split helpers.
 *
 * The split boundary is supplied by the active MMU backend. ARM32 currently
 * implements it with split TTBR0/TTBR1; future architectures should keep the
 * public meaning ("below is user, above is kernel") while providing their own
 * backend value.
 */
vaddr_t get_split_boundary(void);

static inline bool memory_is_user_address(vaddr_t addr)
{
    return addr < get_split_boundary();
}

static inline bool memory_is_kernel_address(vaddr_t addr)
{
    return addr >= get_split_boundary();
}

/* VMA flags */
#define VMA_READ    (1 << 0)
#define VMA_WRITE   (1 << 1)
#define VMA_EXEC    (1 << 2)
#define VMA_KERNEL  (1 << 3)
#define VMA_SHARED  (1 << 4)
#define VMA_LAZY    (1 << 5)

/*
 * ASID aliases. The active MMU backend owns the concrete ASID width and the
 * reserved kernel slot; generic code keeps using these names during the
 * multi-arch split.
 */
#define ASID_KERNEL     ARCH_ASID_KERNEL
#define ASID_MIN_USER   ARCH_ASID_MIN_USER
#define ASID_MAX        ARCH_ASID_MAX

#define MAX_TEMP_MAPPINGS 8

extern uint32_t kernel_memory_size;

typedef struct kernel_context_save {
    uint32_t saved_ttbr0;
    uint32_t saved_asid;
    bool context_switched;
} kernel_context_save_t;

#define MAX_ORDER 10  // max block size = 2^10 * PAGE_SIZE = 4 MB
#define BUDDY_BASE 0x54010000  // base de l'arène mémoire du buddy allocator
#define BUDDY_SIZE (1 << MAX_ORDER) * PAGE_SIZE

typedef struct buddy_block {
    struct buddy_block* next;
} buddy_block_t;

struct page_info {
    uint8_t used     : 1;  // page allouée ou libre
    size_t size        ;  // buddy order (si utilisé)
    uint8_t reserved : 1;  // marquée réservée (ex: DTB)
    uint16_t refcount;     // references physiques (COW, mappings partages)
    paddr_t start;
}__attribute__((packed));

kernel_context_save_t switch_to_kernel_context(void);
void restore_from_kernel_context(kernel_context_save_t save);
void restore_user_context(uint32_t saved_asid);

/* Memory management */
bool init_memory(void);
void* allocate_page(void);
void free_page(void* page_addr);
void* allocate_pages(uint32_t num_pages);
void free_pages(void* page_addr, uint32_t num_pages);
bool page_is_buddy_page(void* page_addr);
uint16_t page_ref_count(void* page_addr);
int page_ref_inc(void* page_addr);
uint16_t page_ref_dec(void* page_addr);
uint32_t get_kernel_memory_size(void);
uint32_t get_free_page_count(void);
uint32_t get_total_page_count(void);
uint32_t get_allocated_page_count(void);
uint32_t get_freed_page_count(void);


/* Virtual memory avec support ASID */
vm_space_t* create_vm_space(void);
void destroy_vm_space(vm_space_t* vm);
vm_space_t* fork_vm_space(vm_space_t* parent_vm);
vma_t* create_vma(vm_space_t* vm, vaddr_t start, uint32_t size, uint32_t flags);
int remove_vma(vm_space_t* vm, vaddr_t start, vaddr_t end);
vaddr_t vm_find_free_range(vm_space_t* vm, vaddr_t hint, uint32_t size,
                           vaddr_t base, vaddr_t limit);
int vm_unmap_range(vm_space_t* vm, vaddr_t start, uint32_t size);
vma_t* find_vma(vm_space_t* vm, vaddr_t addr);
uint32_t vm_virtual_kb(vm_space_t* vm);
uint32_t vm_resident_kb(vm_space_t* vm);
uint32_t vm_page_table_count(vm_space_t* vm);
int handle_cow_fault(vaddr_t fault_addr);
int handle_user_stack_fault(vaddr_t fault_addr);
int handle_lazy_anon_fault(vaddr_t fault_addr, bool is_write);

/* Nouvelles fonctions pour ASID */
void switch_to_vm_space(vm_space_t *vm);
uint32_t get_vm_asid(vm_space_t *vm);
bool validate_vm_space(vm_space_t *vm);
void debug_asid_usage(void);

/* MMU avec support split TTBR */
bool setup_mmu(void);
void switch_address_space(pgdir_t pgdir);                           /* TTBR0 seulement */
void switch_address_space_with_asid(pgdir_t pgdir, uint32_t asid);   /* TTBR0 + ASID */
int map_user_page(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid);
int map_user_page_readonly(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid);
int remap_user_page(pgdir_t pgdir, vaddr_t vaddr, paddr_t phys_addr, uint32_t vma_flags, uint32_t asid);
int set_user_page_readonly(pgdir_t pgdir, vaddr_t vaddr, uint32_t asid);
int set_user_page_writable(pgdir_t pgdir, vaddr_t vaddr, uint32_t asid);
paddr_t get_physical_address(pgdir_t pgdir, vaddr_t vaddr);
void debug_mmu_state(void);
void unmap_temp_pages_contiguous(vaddr_t base_vaddr, int num_pages);
vaddr_t map_temp_pages_contiguous(paddr_t phys_addr, int num_pages);

uint32_t get_current_ttrb0(void);

vaddr_t map_user_to_kernel(pgdir_t pgdir, vaddr_t vaddr);
void unmap_temp_user_page(void);

/* MMU helper functions - implémentées dans mmu.c */
void invalidate_tlb_all(void);
void invalidate_tlb_page(vaddr_t vaddr);
void invalidate_tlb_page_asid(vaddr_t vaddr, uint32_t asid);  /* NOUVEAU */
void invalidate_tlb_asid(uint32_t asid);                       /* NOUVEAU */

/* Address-space register access functions */
uint32_t get_ttbr0(void);
void set_ttbr0(uint32_t ttbr0);

/* ASID management functions */
uint32_t vm_allocate_asid(void);
void vm_free_asid(uint32_t asid);
uint32_t vm_get_current_asid(void);
void set_current_asid(uint32_t asid);

/* Temporary mapping helpers */
vaddr_t map_temp_page(paddr_t phys_addr);
void unmap_temp_page(void* temp_vaddr);
vaddr_t map_temp_user_page(paddr_t phys_addr);
void unmap_temp_user_page();
paddr_t get_phys_from_temp_mapping(vaddr_t temp_ptr);
uint32_t get_current_asid(void);
void preallocate_temp_mapping_system(void);
void create_l2_access_zone(void);
void setup_temp_mapping_slots(void);
void init_temp_mapping_system(void);
vaddr_t map_temp_page_large(paddr_t phys_addr, uint32_t size);

/* Kernel malloc */
void init_kernel_heap(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* kcalloc(size_t nmemb, size_t size);
void* krealloc(void* ptr, size_t size);
void* kzalloc(size_t size);

/* Memory info */
uint32_t get_free_page_count(void);
uint32_t get_total_page_count(void);
uint32_t get_allocated_page_count(void);
uint32_t get_freed_page_count(void);

/* ELF helper functions */
void zero_fill_bss(vm_space_t* vm, vaddr_t vaddr, uint32_t size);

/* Memory detection */
uint32_t detect_memory(void);

/* Variable globale DTB */
extern uint32_t dtb_address;

void kheap_stats(void);

void dump_kernel_stack(int depth);
void debug_kernel_stack_integrity(const char* location);
void check_memory_corruption(void);
void setup_svc_stack(void);

void hexdump(const void* addr, size_t n) ;

#endif /* _KERNEL_MEMORY_H */

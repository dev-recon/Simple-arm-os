/* include/kernel/memory.h - Version avec support split TTBR et ASID */
#ifndef _KERNEL_MEMORY_H
#define _KERNEL_MEMORY_H

#include <kernel/types.h>

typedef struct {
    uint32_t* bitmap;
    uint32_t total_pages;
    uint32_t free_pages;
    uint32_t start_addr;
    uint32_t bitmap_pages;  /* Nombre de pages utilisees par le bitmap */
} __attribute__((aligned(4))) physical_allocator_t;

/* Virtual Memory Area */
typedef struct vma {
    uint32_t start;        /* 4 bytes */
    uint32_t end;          /* 4 bytes */
    uint32_t flags;        /* 4 bytes */
    uint32_t padding1;     /* 4 bytes - pour aligner sur 8 */
    struct vma* next;      /* 4 bytes */
    uint32_t padding2;     /* 4 bytes - pour compléter 8 */
} __attribute__((aligned(8))) vma_t;
/* Taille: 24 bytes - alignée sur 8 OK */

typedef struct vm_space {
    uint32_t* pgdir;       /* 4 bytes - TTBR0 seulement */
    vma_t* vma_list;       /* 4 bytes */
    uint32_t heap_start;   /* 4 bytes */
    uint32_t heap_end;     /* 4 bytes */
    uint32_t brk;          /* 4 bytes */
    uint32_t stack_start;  /* 4 bytes */
    uint32_t asid;         /* 4 bytes - NOUVEAU: ASID du processus */
    uint32_t padding;      /* 4 bytes pour aligner sur 8 */
} __attribute__((aligned(8))) vm_space_t;
/* Taille: 32 bytes - alignée sur 8 OK */

/* VMA flags */
#define VMA_READ    (1 << 0)
#define VMA_WRITE   (1 << 1)
#define VMA_EXEC    (1 << 2)
#define VMA_KERNEL  (1 << 3)

/* ASID constants */
#define ASID_KERNEL     254       /* ASID réservé pour le noyau */
#define ASID_MIN_USER   1       /* Premier ASID utilisateur */
#define ASID_MAX        255     /* ASID maximum (8 bits) */

#define MAX_TEMP_MAPPINGS 8

/*
 * Configuration correcte des registres TTBR avec TTBCR.N=2
 */

// Définitions des bits TTBR
#define TTBR_RGN_OUTER_NC    (0b00 << 3)  // Non-cacheable
#define TTBR_RGN_OUTER_WBWA  (0b01 << 3)  // Write-back write-allocate
#define TTBR_RGN_OUTER_WT    (0b10 << 3)  // Write-through
#define TTBR_RGN_OUTER_WB    (0b11 << 3)  // Write-back

#define TTBR_SHAREABLE       (1 << 1)     // Bit S - Shareable
#define TTBR_CACHEABLE       (1 << 0)     // Bit C - Cacheable

// Pour TTBR avec TTBCR.N > 0, bits IRGN sont dans TTBCR, pas TTBR
#define TTBCR_IRGN0_NC       (0b00 << 8)  // Inner non-cacheable TTBR0
#define TTBCR_IRGN0_WBWA     (0b01 << 8)  // Inner write-back write-allocate TTBR0
#define TTBCR_IRGN0_WT       (0b10 << 8)  // Inner write-through TTBR0
#define TTBCR_IRGN0_WB       (0b11 << 8)  // Inner write-back TTBR0

#define TTBCR_IRGN1_NC       (0b00 << 10) // Inner non-cacheable TTBR1
#define TTBCR_IRGN1_WBWA     (0b01 << 10) // Inner write-back write-allocate TTBR1
#define TTBCR_IRGN1_WT       (0b10 << 10) // Inner write-through TTBR1
#define TTBCR_IRGN1_WB       (0b11 << 10) // Inner write-back TTBR1

extern uint32_t* kernel_pgdir;  /* Page directory du kernel (TTBR1) */
extern uint32_t* ttbr0_pgdir;   /* Page directory du kernel (TTBR0) */
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
    uint8_t refcount;      // pour un ref counting basique
    uint32_t start;
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
uint32_t get_kernel_memory_size(void);


/* Virtual memory avec support ASID */
vm_space_t* create_vm_space(void);
void destroy_vm_space(vm_space_t* vm);
vm_space_t* fork_vm_space(vm_space_t* parent_vm);
vma_t* create_vma(vm_space_t* vm, uint32_t start, uint32_t size, uint32_t flags);
vma_t* find_vma(vm_space_t* vm, uint32_t addr);

/* Nouvelles fonctions pour ASID */
void switch_to_vm_space(vm_space_t *vm);
uint32_t get_vm_asid(vm_space_t *vm);
bool validate_vm_space(vm_space_t *vm);
void debug_asid_usage(void);

/* MMU avec support split TTBR */
bool setup_mmu(void);
void switch_address_space(uint32_t* pgdir);                           /* TTBR0 seulement */
void switch_address_space_with_asid(uint32_t* pgdir, uint32_t asid);   /* TTBR0 + ASID */
int map_user_page(uint32_t* pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags, uint32_t asid);
void map_kernel_page(uint32_t vaddr, uint32_t phys_addr);
uint32_t get_physical_address(uint32_t* pgdir, uint32_t vaddr);
void debug_mmu_state(void);
void unmap_temp_pages_contiguous(uint32_t base_vaddr, int num_pages);
uint32_t map_temp_pages_contiguous(uint32_t phys_addr, int num_pages);

uint32_t* get_page_entry_arm(uint32_t* pgdir, uint32_t vaddr);
int check_page_permissions(uint32_t* pgdir, uint32_t vaddr);
uint32_t get_current_ttrb0(void);

uint32_t map_user_to_kernel(uint32_t *pgdir, uint32_t vaddr);
void unmap_temp_user_page(void);
uint32_t get_phys_addr_from_pgdir(uint32_t* pgdir, uint32_t vaddr);

uint32_t read_l2_entry(uint32_t *pgdir, uintptr_t vaddr);

/* MMU helper functions - implémentées dans mmu.c */
void invalidate_tlb_all(void);
void invalidate_tlb_page(uint32_t vaddr);
void invalidate_tlb_page_asid(uint32_t vaddr, uint32_t asid);  /* NOUVEAU */
void invalidate_tlb_asid(uint32_t asid);                       /* NOUVEAU */

/* TTBR access functions */
uint32_t get_ttbr0(void);
uint32_t* get_kernel_ttbr0(void);
void set_ttbr0(uint32_t ttbr0);
uint32_t get_L1_index(uint32_t vaddr);
//uint32_t get_ttbr1(void);    /* NOUVEAU */
//void set_ttbr1(uint32_t ttbr1);    /* NOUVEAU */

/* Fonctions d'accès aux page directories */
uint32_t* get_kernel_pgdir(void);        /* NOUVEAU - retourne TTBR1 */

/* ASID management functions */
uint32_t vm_allocate_asid(void);
void vm_free_asid(uint32_t asid);
uint32_t vm_get_current_asid(void);
void set_current_asid(uint32_t asid);

/* Temporary mapping helpers */
uint32_t map_temp_page(uint32_t phys_addr);
void unmap_temp_page(void* temp_vaddr);
uint32_t map_temp_user_page(uint32_t phys_addr);
void unmap_temp_user_page();
uint32_t get_phys_from_temp_mapping(uint32_t temp_ptr);
uint32_t get_current_asid(void);
void preallocate_temp_mapping_system(void);
void create_l2_access_zone(void);
void setup_temp_mapping_slots(void);
void init_temp_mapping_system(void);
uint32_t map_temp_page_large(uint32_t phys_addr, uint32_t size);

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

/* ELF helper functions */
void zero_fill_bss(vm_space_t* vm, uint32_t vaddr, uint32_t size);

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
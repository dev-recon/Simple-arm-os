/* include/kernel/memory.h - Version avec support split TTBR et ASID */
#ifndef _KERNEL_MEMORY_H
#define _KERNEL_MEMORY_H

#include <kernel/types.h>

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
    uint32_t stack_start;  /* 4 bytes */
    uint32_t asid;         /* 4 bytes - NOUVEAU: ASID du processus */
    uint32_t padding[2];   /* 8 bytes pour aligner sur 8 */
} __attribute__((aligned(8))) vm_space_t;
/* Taille: 32 bytes - alignée sur 8 OK */

/* VMA flags */
#define VMA_READ    (1 << 0)
#define VMA_WRITE   (1 << 1)
#define VMA_EXEC    (1 << 2)
#define VMA_KERNEL  (1 << 3)

/* ASID constants */
#define ASID_KERNEL     0       /* ASID réservé pour le noyau */
#define ASID_MIN_USER   1       /* Premier ASID utilisateur */
#define ASID_MAX        255     /* ASID maximum (8 bits) */

#define MAX_TEMP_MAPPINGS 16

extern uint32_t* kernel_pgdir;  /* Page directory du kernel (TTBR1) */

/* Memory management */
bool init_memory(void);
void* allocate_physical_page(void);
void free_physical_page(void* page_addr);
void* allocate_contiguous_pages(uint32_t num_pages);
void free_contiguous_pages(void* page_addr, uint32_t num_pages);

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
int map_user_page(uint32_t* pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags);
void map_kernel_page(uint32_t vaddr, uint32_t phys_addr);
uint32_t get_physical_address(uint32_t* pgdir, uint32_t vaddr);
void debug_mmu_state(void);

uint32_t* get_page_entry_arm(uint32_t* pgdir, uint32_t vaddr);
int check_page_permissions(uint32_t* pgdir, uint32_t vaddr);
uint32_t get_current_ttrb0(void);

/* MMU helper functions - implémentées dans mmu.c */
void invalidate_tlb_all(void);
void invalidate_tlb_page(uint32_t vaddr);
void invalidate_tlb_page_asid(uint32_t vaddr, uint32_t asid);  /* NOUVEAU */
void invalidate_tlb_asid(uint32_t asid);                       /* NOUVEAU */

/* TTBR access functions */
uint32_t get_ttbr0(void);
void set_ttbr0(uint32_t ttbr0);
//uint32_t get_ttbr1(void);    /* NOUVEAU */
//void set_ttbr1(uint32_t ttbr1);    /* NOUVEAU */

/* Fonctions d'accès aux page directories */
uint32_t* get_kernel_pgdir(void);        /* NOUVEAU - retourne TTBR1 */

/* ASID management functions */
uint32_t vm_allocate_asid(void);
void vm_free_asid(uint32_t asid);
uint32_t vm_get_current_asid(void);

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

#endif /* _KERNEL_MEMORY_H */
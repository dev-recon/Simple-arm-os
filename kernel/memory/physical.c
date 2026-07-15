/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/memory/physical.c
 * Layer: Kernel / memory management
 *
 * Responsibilities:
 * - Manage physical pages, virtual address spaces, MMU mappings, and ASIDs.
 * - Support user mappings, page faults, and copy-on-write.
 *
 * Notes:
 * - TLB, ASID, and TTBR changes are global stability concerns.
 */

#include <kernel/memory.h>
#include <kernel/address_space.h>
#include <kernel/kprintf.h>
#include <kernel/linker.h>
#include <kernel/string.h>
#include <kernel/spinlock.h>

#define PHYS_ARG(value) ((unsigned long)(paddr_t)(value))
#define SIZE_ARG(value) ((unsigned long)(size_t)(value))
#include <kernel/arch_cpu.h>


physical_allocator_t phys_alloc;

static buddy_block_t* free_lists[MAX_ORDER + 1];
paddr_t buddy_base = 0;
struct page_info *page_infos;
static spinlock_t buddy_lock = SPINLOCK_INIT("buddy");

/* Forward declarations des fonctions statiques */
static int set_page_used(uint32_t page_index);
static void set_page_free(uint32_t page_index);
static bool is_page_free(uint32_t page_index);
static void reserve_kernel_pages(void);
static void reserve_bitmap_pages(void);
static void reserve_heap_pages(void);
static void reserve_dtb_pages(void);
static struct page_info* buddy_page_info(void* ptr);
static void buddy_free_locked(void* ptr);
static void account_buddy_alloc(size_t pages);
static void account_buddy_free(size_t pages);
static paddr_t choose_buddy_base(void);
//static void reserve_mmu_pages(void);

static bool mmu_is_enabled(void)
{
    return arch_mmu_enabled();
}

static bool buddy_lock_if_needed(unsigned long *flags)
{
    if (mmu_is_enabled()) {
        spin_lock_irqsave(&buddy_lock, flags);
        return true;
    }

    if (flags)
        *flags = 0;
    return false;
}

static void buddy_unlock_if_needed(bool locked, unsigned long flags)
{
    if (locked)
        spin_unlock_irqrestore(&buddy_lock, flags);
}

static struct page_info* page_info_array(void)
{
    paddr_t phys = (paddr_t)page_infos;

    if (!page_infos) {
        return NULL;
    }

    /*
     * page_infos is allocated while the boot identity mapping is still active.
     * Once the MMU is enabled, the allocator metadata must be reached through
     * the RAM direct-map instead of assuming VA == PA.
     */
    if (mmu_is_enabled()) {
        if (!phys_in_direct_map(phys)) {
            KERROR("buddy: page metadata 0x%lX outside direct map\n",
                   PHYS_ARG(phys));
            return NULL;
        }
        return (struct page_info*)phys_to_virt(phys);
    }

    return page_infos;
}

void* early_alloc(uint32_t size, uint32_t align) {
    // Aligner l’adresse de départ
    paddr_t alloc_base = ALIGN_UP(buddy_base, align);

    // Avancer le pointeur
    buddy_base = ALIGN_UP(alloc_base + size, PAGE_SIZE);

    return (void*)alloc_base;
}

void buddy_init()
{
    buddy_base = choose_buddy_base();

    uint32_t page_info_size = phys_alloc.free_pages * sizeof(struct page_info);

    // Trouve une région libre juste après le kernel (et DTB)
    void* page_info_region = early_alloc(page_info_size,8);
    void* page_info_ = (void*)ALIGN_UP((uintptr_t)page_info_region, 8);

    // Zéro-initialise
    memset(page_info_, 0, page_info_size);

    page_infos = (struct page_info*)page_info_;

    for (int i = 0; i <= MAX_ORDER; i++) {
        free_lists[i] = NULL;
    }

    buddy_base = ALIGN_UP(buddy_base, PAGE_SIZE);

    // Toute la mémoire est d'abord un seul gros bloc
    buddy_block_t* block = (buddy_block_t*)buddy_base;
    block->next = NULL;
    free_lists[MAX_ORDER] = block;
    uint32_t mem_size = detect_memory();
    paddr_t ram_end = physical_ram_start() + mem_size;
    uint32_t buddy_pages = (ram_end - buddy_base) / PAGE_SIZE;

    KINFO("[MEM] Buddy Allocator configuration:\n");
    KINFO("[MEM]   Buddy Base : 0x%lX\n", PHYS_ARG(buddy_base));
    KINFO("[MEM]   RAM End: 0x%lX\n", PHYS_ARG(ram_end));
    KINFO("[MEM]   Buddy Size: %lu\n", SIZE_ARG(ram_end - buddy_base));
    KINFO("[MEM]   Buddy pages: %u\n", buddy_pages);

}

static paddr_t choose_buddy_base(void)
{
    paddr_t ram_start = physical_ram_start();
    paddr_t ram_end = physical_ram_end();
    paddr_t base = ALIGN_UP((paddr_t)FREE_MEMORY_START, PAGE_SIZE);

    /*
     * The physical-page bitmap is carved out before the buddy allocator is
     * initialized. Keep the buddy arena above it; otherwise the page-info array
     * allocated by early_alloc() can overwrite the bitmap on low-RAM platforms.
     */
    if (phys_alloc.start_addr > base)
        base = ALIGN_UP(phys_alloc.start_addr, PAGE_SIZE);

    /*
     * reserve_dtb_pages() may advance buddy_base past a boot DTB. Preserve it
     * when it is inside platform RAM.
     */
    if (buddy_base >= ram_start && buddy_base < ram_end && buddy_base > base)
        base = ALIGN_UP(buddy_base, PAGE_SIZE);

    /*
     * qemu-virt historically kept a fixed high-memory staging area below the
     * buddy allocator. Keep that floor only on platforms where it is actually
     * RAM. Raspberry Pi 2 RAM ends before this address, so the floor must not
     * leak into that port.
     */
    if ((paddr_t)BUDDY_BASE >= ram_start &&
        (paddr_t)BUDDY_BASE < ram_end &&
        (paddr_t)BUDDY_BASE > base) {
        base = ALIGN_UP((paddr_t)BUDDY_BASE, PAGE_SIZE);
    }

    if (base < ram_start)
        base = ram_start;

    if (base >= ram_end) {
        KWARN("[MEM] buddy base 0x%lX outside RAM, falling back to free memory start\n",
              PHYS_ARG(base));
        base = ALIGN_UP((paddr_t)FREE_MEMORY_START, PAGE_SIZE);
    }

    return base;
}

static int get_order(size_t size)
{
    size = ALIGN_UP(size, PAGE_SIZE);
    int order = 0;
    size_t total = PAGE_SIZE;
    while (order < MAX_ORDER && total < size) {
        order++;
        total <<= 1;
    }
    return order;
}

static uintptr_t buddy_of(uintptr_t addr, int order)
{
    return addr ^ (1 << (order + 12));  // 12 = log2(PAGE_SIZE)
}


void* buddy_alloc(size_t num_block) {

    paddr_t ram_end = physical_ram_end();
    uint32_t max_pages = (ram_end - buddy_base) / PAGE_SIZE;
    unsigned long flags;
    bool locked;
    struct page_info *infos;

    //kprintf("\n***********************************************************************\n");
    //kprintf("\n***********************************************************************\n");
    //kprintf("Allocation requested for %u pages\n", num_block);

    if (num_block == 0 || num_block > max_pages) {
        return NULL;
    }

    locked = buddy_lock_if_needed(&flags);
    infos = page_info_array();
    if (!infos) {
        buddy_unlock_if_needed(locked, flags);
        return NULL;
    }

    size_t run_start = 0;
    size_t run_length = 0;

    /*
     * Rechercher une plage contigue libre. L'ancien code avancait avec
     * page_infos[index].size lorsqu'une page occupee etait trouvee plus loin
     * dans la plage candidate. Si la page a index etait libre, sa taille
     * valait zero et la recherche bouclait indefiniment.
     */
    for (size_t index = 0; index < max_pages; ++index) {
        if (!infos[index].used && !infos[index].reserved) {
            if (run_length == 0) {
                run_start = index;
            }
            run_length++;
        } else {
            run_length = 0;
        }

        if (run_length == num_block) {
            paddr_t addr = buddy_base + run_start * PAGE_SIZE;

            // Marque les pages comme utilisées
            for (size_t j = 0; j < num_block; ++j) {
                infos[run_start + j].used = 1;
                infos[run_start + j].start = addr;
                infos[run_start + j].size = num_block;
                infos[run_start + j].refcount = 1;
            }

            account_buddy_alloc(num_block);

            buddy_unlock_if_needed(locked, flags);

            void *zero_addr = (void *)addr;
            if (mmu_is_enabled()) {
                if (!phys_in_direct_map(addr)) {
                    KERROR("buddy_alloc: phys 0x%lX outside direct map\n",
                           PHYS_ARG(addr));
                    return (void *)addr;
                }
                zero_addr = (void *)phys_to_virt(addr);
            }
            memset(zero_addr, 0, num_block * PAGE_SIZE);
            //kprintf("Found block at 0x%08X\n", addr);
            //kprintf("page_infos[%d].used = %u\n", run_start, page_infos[run_start].used);
            //kprintf("page_infos[%d].start = 0x%08X\n", run_start, page_infos[run_start].start);
            //kprintf("page_infos[%d].size = %u\n", run_start, page_infos[run_start].size);

            return (void*)addr;
        }
    }

    buddy_unlock_if_needed(locked, flags);
    return NULL; // Aucun bloc disponible
}

static void buddy_free_locked(void* ptr) {
    paddr_t ram_end = physical_ram_end();
    uint32_t max_pages = (ram_end - buddy_base) / PAGE_SIZE;
    paddr_t addr = (paddr_t)ptr;
    struct page_info *infos;

    if (!ptr || (addr & (PAGE_SIZE - 1)) || addr < buddy_base || addr >= ram_end) {
        return;
    }

    infos = page_info_array();
    if (!infos) {
        return;
    }

    size_t index = (addr - buddy_base) / PAGE_SIZE;

    //kprintf("\n***********************************************************************\n");
    //kprintf("\n***********************************************************************\n");
    //kprintf("Free requested for 0x%08X\n", addr);
    //kprintf("Size to be freed %u at index %u\n", page_infos[index].size, index);

    size_t block_size = infos[index].size;
    if (block_size == 0 || block_size > max_pages) {
        return;
    }

    paddr_t start_addr = infos[index].start;
    if (start_addr != addr) {
        index = (start_addr - buddy_base) / PAGE_SIZE;
        //kprintf("PTR is not at the start of the allocated region\n");
        //kprintf("Real start at 0x%08X\n", start_addr);
        //kprintf("Size to be freed %u at index %u\n", page_infos[index].size, index);
    }

    for (size_t i = 0; i < block_size; ++i) {
        infos[index + i].used = 0;
        infos[index + i].size = 0;
        infos[index + i].refcount = 0;
    }

    infos[index].start = 0;
    infos[index].size = 0;

    account_buddy_free(block_size);
}

void buddy_free(void* ptr) {
    unsigned long flags;
    bool locked;

    locked = buddy_lock_if_needed(&flags);
    buddy_free_locked(ptr);
    buddy_unlock_if_needed(locked, flags);
}

static struct page_info* buddy_page_info(void* ptr)
{
    paddr_t addr = (paddr_t)ptr;
    paddr_t ram_end = physical_ram_end();
    uint32_t max_pages = (ram_end - buddy_base) / PAGE_SIZE;
    struct page_info *infos = page_info_array();
    uint32_t index;

    if (!infos) {
        return NULL;
    }

    if (!ptr || (addr & (PAGE_SIZE - 1)) || addr < buddy_base || addr >= ram_end) {
        return NULL;
    }

    index = (addr - buddy_base) / PAGE_SIZE;
    if (index >= max_pages || infos[index].reserved || !infos[index].used) {
        return NULL;
    }

    return &infos[index];
}

bool page_is_buddy_page(void* page_addr)
{
    return buddy_page_info(page_addr) != NULL;
}

uint16_t page_ref_count(void* page_addr)
{
    unsigned long flags;
    bool locked;
    uint16_t refs;

    locked = buddy_lock_if_needed(&flags);
    struct page_info* info = buddy_page_info(page_addr);
    refs = info ? info->refcount : 0;
    buddy_unlock_if_needed(locked, flags);
    return refs;
}

int page_ref_inc(void* page_addr)
{
    unsigned long flags;
    bool locked;
    int ret = 0;

    locked = buddy_lock_if_needed(&flags);
    struct page_info* info = buddy_page_info(page_addr);
    if (!info || info->refcount == 0xFFFFu) {
        ret = -1;
    } else {
        info->refcount++;
    }

    buddy_unlock_if_needed(locked, flags);
    return ret;
}

uint16_t page_ref_dec(void* page_addr)
{
    unsigned long flags;
    bool locked;
    uint16_t refs = 0;

    locked = buddy_lock_if_needed(&flags);
    struct page_info* info = buddy_page_info(page_addr);
    if (info && info->refcount > 0) {
        info->refcount--;
        refs = info->refcount;
    }

    buddy_unlock_if_needed(locked, flags);
    return refs;
}


bool init_memory(void)
{
    paddr_t mem_start = physical_ram_start();
    uint32_t mem_size = detect_memory();    // UNCOMMENT FOR PROD

    // GDB DEBUG BLOCK - COMMENT FOR PROD
    //dtb_address = 0x48000000;
    //uint32_t mem_size = 2 * 1024 * 1024 * 1024u;  // 2GB total (0-2GB)
    //kernel_memory_size = mem_size ;  // FIX IT - For use of GDB
    // END GDB DEBUG BLOCK - COMMENT FOR PROD

    uint32_t bitmap_size_words;
    uint32_t bitmap_size_bytes;
    uint32_t i;

    KINFO("[MEM] Initializing physical memory allocator...\n");
    KINFO("[MEM] RAM: 0x%lX - 0x%lX (%u MB)\n",
          PHYS_ARG(mem_start), PHYS_ARG(mem_start + mem_size),
          mem_size / (1024 * 1024));

    paddr_t bitmap_start = ALIGN_UP((paddr_t)FREE_MEMORY_START, PAGE_SIZE);
    paddr_t ram_end = mem_start + mem_size;
    
    /* Bitmap: 1 bit per page */
    phys_alloc.total_pages = mem_size / PAGE_SIZE;
    bitmap_size_words = (phys_alloc.total_pages + 31) / 32;
    bitmap_size_bytes = bitmap_size_words * 4;
    phys_alloc.bitmap_pages = (bitmap_size_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    if (bitmap_start < mem_start || bitmap_start >= ram_end) {
        KERROR("[MEM] Bitmap start outside platform RAM!\n");
        return false;
    }

    phys_alloc.start_addr = bitmap_start + (phys_alloc.bitmap_pages * PAGE_SIZE);
    if (phys_alloc.start_addr > ram_end) {
        KERROR("[MEM] Bitmap consumes all platform RAM!\n");
        return false;
    }
    phys_alloc.total_pages = (ram_end - phys_alloc.start_addr) / PAGE_SIZE;
    
    /* Placer le bitmap APReS le kernel et heap, pas a la fin de la RAM */
    //extern uint32_t __free_memory_start;

    phys_alloc.bitmap = (uint32_t*)bitmap_start;
    
    KINFO("[MEM] Bitmap configuration:\n");
    KINFO("[MEM]   Total pages: %u\n", phys_alloc.total_pages);
    KINFO("[MEM]   Bitmap words: %u\n", bitmap_size_words);
    KINFO("[MEM]   Bitmap bytes: %u\n", bitmap_size_bytes);
    KINFO("[MEM]   Bitmap pages: %u\n", phys_alloc.bitmap_pages);
    KINFO("[MEM]   Bitmap address: 0x%lX\n",
          PHYS_ARG((paddr_t)phys_alloc.bitmap));
    
    /* Verifier que le bitmap ne depasse pas la RAM */
    if ((paddr_t)phys_alloc.bitmap + bitmap_size_bytes > mem_start + mem_size) {
        KERROR("[MEM] Bitmap would extend beyond RAM!\n");
        return false;
    }
    
    /* Mark all pages as free initially */
    for (i = 0; i < bitmap_size_words; i++) {
        phys_alloc.bitmap[i] = 0;
    }
    
    phys_alloc.free_pages = phys_alloc.total_pages;
    
    KINFO("[MEM] Initial state: %u pages (%lu MB) free\n",
          phys_alloc.free_pages,
          SIZE_ARG((phys_alloc.free_pages * PAGE_SIZE) / (1024 * 1024)));

    
    /* Reserve kernel pages */
    reserve_kernel_pages();
    
    /* Reserve bitmap pages */
    reserve_bitmap_pages();
        
    if (!init_kernel_heap()) {
        KERROR("[MEM] Kernel heap initialization failed\n");
        return false;
    }

    reserve_heap_pages();

    reserve_dtb_pages();

    //reserve_mmu_pages();

    KINFO("[MEM] Final state: %u pages (%lu MB) free\n",
          phys_alloc.free_pages,
          SIZE_ARG((phys_alloc.free_pages * PAGE_SIZE) / (1024 * 1024)));

    buddy_init();
    
    return true;
}

static void reserve_kernel_pages(void)
{
    KINFO("[MEM] Reserving kernel pages...\n");
    
    /* Utiliser les symboles du linker script */
    extern uint32_t __text_start, __text_end;
    extern uint32_t __data_start, __data_end;
    extern uint32_t __bss_start, __bss_end;
    
    paddr_t kernel_start = KERNEL_PHYSICAL_START;
    paddr_t kernel_end = KERNEL_PHYSICAL_END;
    size_t kernel_size = KERNEL_PHYSICAL_SIZE;
    paddr_t text_start = (paddr_t)(uintptr_t)&__text_start;
    paddr_t text_end = (paddr_t)(uintptr_t)&__text_end;
    paddr_t data_start = (paddr_t)(uintptr_t)&__data_start;
    paddr_t data_end = (paddr_t)(uintptr_t)&__data_end;
    paddr_t bss_start = (paddr_t)(uintptr_t)&__bss_start;
    paddr_t bss_end = (paddr_t)(uintptr_t)&__bss_end;
    
    KINFO("[MEM] Kernel layout from linker:\n");
    KINFO("[MEM]   Kernel start:  0x%lX\n", PHYS_ARG(kernel_start));
    KINFO("[MEM]   Kernel end:    0x%lX\n", PHYS_ARG(kernel_end));
    KINFO("[MEM]   Kernel size:   %u bytes (%u KB)\n",
          (uint32_t)kernel_size, (uint32_t)(kernel_size / 1024));
    
    /* Afficher les sections detaillees */
    KINFO("[MEM] Kernel sections:\n");
    KINFO("[MEM]   .text:  0x%lX - 0x%lX (%lu bytes)\n",
          PHYS_ARG(text_start), PHYS_ARG(text_end),
          SIZE_ARG(text_end - text_start));
    KINFO("[MEM]   .data:  0x%lX - 0x%lX (%lu bytes)\n",
          PHYS_ARG(data_start), PHYS_ARG(data_end),
          SIZE_ARG(data_end - data_start));
    KINFO("[MEM]   .bss:   0x%lX - 0x%lX (%lu bytes)\n",
          PHYS_ARG(bss_start), PHYS_ARG(bss_end),
          SIZE_ARG(bss_end - bss_start));
    
    /* Verifications de securite */
    if (kernel_end <= phys_alloc.start_addr) {
        KINFO("[MEM] Kernel image is below managed RAM start; already excluded\n");
        return;
    }
    
    paddr_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    if (kernel_end > ram_end) {
        KERROR("[MEM] Kernel extends beyond RAM!\n");
        KINFO("[MEM]   Kernel end: 0x%lX, RAM end: 0x%lX\n",
              PHYS_ARG(kernel_end), PHYS_ARG(ram_end));
        return;
    }
    
    /* Reserver depuis le debut de la RAM jusqu'a la fin du kernel */
    paddr_t kernel_start_page = phys_alloc.start_addr;  /* Debut de la RAM */
    paddr_t kernel_end_page = ALIGN_UP(kernel_end, PAGE_SIZE);
    
    KINFO("[MEM] Reserving from start of RAM to end of kernel:\n");
    KINFO("[MEM]   Start page: 0x%lX\n", PHYS_ARG(kernel_start_page));
    KINFO("[MEM]   End page:   0x%lX\n", PHYS_ARG(kernel_end_page));
    
    /* Calculer le nombre de pages */
    uint32_t pages_to_reserve = (kernel_end_page - kernel_start_page) / PAGE_SIZE;
    KINFO("[MEM]   Pages to reserve: %u\n", pages_to_reserve);
    
    /* Reserver les pages */
    uint32_t pages_reserved = 0;
    paddr_t addr;
    
    for (addr = kernel_start_page; addr < kernel_end_page; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            KERROR("[MEM] Page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    KINFO("[MEM] Kernel pages reserved: %u/%u\n", pages_reserved, pages_to_reserve);
}

static void reserve_dtb_pages(void)
{
    KINFO("[MEM] Reserving dtb pages...\n");
    
    /* Utiliser les symboles du linker script */
    extern uintptr_t dtb_address;
    
    paddr_t dtb_start = dtb_address;
    uint32_t dtb_size = (uint32_t)0x100000;
    paddr_t dtb_end = dtb_start + dtb_size;
    paddr_t managed_start = phys_alloc.start_addr;
    paddr_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;

    
    KINFO("[MEM] DTB layout from %s:\n", arch_platform_name());
    KINFO("[MEM]   DTB start:  0x%lX\n", PHYS_ARG(dtb_start));
    KINFO("[MEM]   DTB end:    0x%lX\n", PHYS_ARG(dtb_start + dtb_size));
    KINFO("[MEM]   DTB size:   %u bytes (%u KB)\n", dtb_size, dtb_size / 1024);
    
    if (dtb_start == 0) {
        KWARN("[MEM] No boot DTB address recorded, skipping DTB reservation\n");
        return;
    }

    if (dtb_end <= managed_start || dtb_start >= ram_end) {
        KWARN("[MEM] DTB outside managed RAM, skipping reservation\n");
        KINFO("[MEM]   DTB: 0x%lX-0x%lX, managed RAM: 0x%lX-0x%lX\n",
              PHYS_ARG(dtb_start), PHYS_ARG(dtb_end),
              PHYS_ARG(managed_start), PHYS_ARG(ram_end));
        return;
    }

    if (dtb_start < managed_start)
        dtb_start = managed_start;
    if (dtb_end > ram_end)
        dtb_end = ram_end;
    
    /* Reserver depuis le debut de la RAM jusqu'a la fin du kernel */
    paddr_t dtb_start_page = ALIGN_DOWN(dtb_start, PAGE_SIZE);
    paddr_t dtb_end_page = ALIGN_UP(dtb_end, PAGE_SIZE);
    buddy_base = ALIGN_UP(dtb_end_page + PAGE_SIZE, PAGE_SIZE) ; 
    
    KINFO("[MEM] Reserving from start of DTB to end of DTB:\n");
    KINFO("[MEM]   Start page: 0x%lX\n", PHYS_ARG(dtb_start_page));
    KINFO("[MEM]   End page:   0x%lX\n", PHYS_ARG(dtb_end_page));
    KINFO("[MEM]   buddy_base:   0x%lX\n", PHYS_ARG(buddy_base));
    
    /* Calculer le nombre de pages */
    uint32_t pages_to_reserve = (dtb_end_page - dtb_start_page) / PAGE_SIZE;
    KINFO("[MEM]   Pages to reserve: %u\n", pages_to_reserve);
    
    /* Reserver les pages */
    uint32_t pages_reserved = 0;
    paddr_t addr;
    
    for (addr = dtb_start_page; addr < dtb_end_page; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            KERROR("[MEM] Page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    KINFO("[MEM] DTB pages reserved: %u/%u\n", pages_reserved, pages_to_reserve);
}


static void reserve_bitmap_pages(void)
{
    KINFO("[MEM] Reserving bitmap pages...\n");
    
    paddr_t bitmap_start = (paddr_t)phys_alloc.bitmap;
    paddr_t bitmap_end = bitmap_start + (phys_alloc.bitmap_pages * PAGE_SIZE);
    paddr_t managed_start = phys_alloc.start_addr;
    paddr_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    
    KINFO("[MEM] Bitmap region: 0x%lX - 0x%lX (%u pages)\n",
          PHYS_ARG(bitmap_start), PHYS_ARG(bitmap_end),
          phys_alloc.bitmap_pages);

    if (bitmap_end <= managed_start || bitmap_start >= ram_end) {
        KINFO("[MEM] Bitmap is outside managed page range, already excluded\n");
        return;
    }

    if (bitmap_start < managed_start)
        bitmap_start = managed_start;
    if (bitmap_end > ram_end)
        bitmap_end = ram_end;
    
    uint32_t pages_reserved = 0;
    paddr_t addr;
    
    for (addr = bitmap_start; addr < bitmap_end; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            KERROR("[MEM] Bitmap page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    KINFO("[MEM] Bitmap pages reserved: %u/%u\n", pages_reserved, phys_alloc.bitmap_pages);
}

static void reserve_heap_pages(void)
{
    extern uint8_t* heap_base;
    extern size_t heap_size;
    
    if (!heap_base || heap_size == 0) {
        KWARN("[MEM] Heap not initialized, skipping reservation\n");
        return;
    }
    
    paddr_t heap_start = (paddr_t)heap_base;
    paddr_t heap_end = heap_start + heap_size;
    paddr_t managed_start = phys_alloc.start_addr;
    paddr_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    
    KINFO("[MEM] === HEAP RESERVATION ===\n");
    KINFO("[MEM]   Heap start: 0x%lX\n", PHYS_ARG(heap_start));
    KINFO("[MEM]   Heap end:   0x%lX\n", PHYS_ARG(heap_end));
    KINFO("[MEM]   Heap size:  %lu MB\n",
          SIZE_ARG(heap_size / (1024 * 1024)));

    if (heap_end <= managed_start) {
        KINFO("[MEM] Heap below managed RAM start; already excluded\n");
        KINFO("[MEM]   Heap: 0x%lX-0x%lX, managed RAM: 0x%lX-0x%lX\n",
              PHYS_ARG(heap_start), PHYS_ARG(heap_end),
              PHYS_ARG(managed_start), PHYS_ARG(ram_end));
        return;
    }

    if (heap_start >= ram_end) {
        KWARN("[MEM] Heap outside platform RAM, skipping reservation\n");
        KINFO("[MEM]   Heap: 0x%lX-0x%lX, managed RAM: 0x%lX-0x%lX\n",
              PHYS_ARG(heap_start), PHYS_ARG(heap_end),
              PHYS_ARG(managed_start), PHYS_ARG(ram_end));
        return;
    }

    if (heap_start < managed_start)
        heap_start = managed_start;
    if (heap_end > ram_end)
        heap_end = ram_end;
    
    uint32_t reserved_count = 0;
    for (paddr_t addr = heap_start; addr < heap_end; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            KERROR("[MEM] Heap page index %u out of range!\n", page_index);
            continue;
        }
        
        if (set_page_used(page_index)) {
            reserved_count++;
        } else {
            KWARN("[MEM] Page %u already reserved\n", page_index);
        }
    }
    
    KINFO("[MEM] Heap reservation complete: %u pages reserved\n", reserved_count);
    KINFO("[MEM] Free pages remaining: %u\n", phys_alloc.free_pages);
}

static int set_page_used(uint32_t page_index)
{
    uint32_t word_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    if (!(phys_alloc.bitmap[word_index] & (1 << bit_index))) {
        phys_alloc.bitmap[word_index] |= (1 << bit_index);
        phys_alloc.free_pages--;
        return 1;
    }
    return 0;
}

static void set_page_free(uint32_t page_index)
{
    uint32_t word_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    
    if (phys_alloc.bitmap[word_index] & (1 << bit_index)) {
        phys_alloc.bitmap[word_index] &= ~(1 << bit_index);
        phys_alloc.free_pages++;
    }
}

static bool is_page_free(uint32_t page_index)
{
    uint32_t word_index = page_index / 32;
    uint32_t bit_index = page_index % 32;
    //KINFO("[MEM] INFO: is page free index %d\n",page_index);
    return !(phys_alloc.bitmap[word_index] & (1 << bit_index));
}

static void account_buddy_alloc(size_t pages)
{
    if (pages > phys_alloc.free_pages) {
        phys_alloc.free_pages = 0;
    } else {
        phys_alloc.free_pages -= pages;
    }

    phys_alloc.pages_allocated += pages;
}

static void account_buddy_free(size_t pages)
{
    if (pages > phys_alloc.total_pages - phys_alloc.free_pages) {
        phys_alloc.free_pages = phys_alloc.total_pages;
    } else {
        phys_alloc.free_pages += pages;
    }

    phys_alloc.pages_freed += pages;
}


void* allocate_page(void)
{
    return buddy_alloc(1);
}

void free_page(void* page_addr)
{
    unsigned long flags;
    bool locked;
    struct page_info* info;

    if (!page_addr) {
        return;
    }

    locked = buddy_lock_if_needed(&flags);
    info = buddy_page_info(page_addr);
    if (!info) {
        buddy_unlock_if_needed(locked, flags);
        return;
    }

    if (info->refcount > 0)
        info->refcount--;

    if (info->refcount == 0) {
        buddy_free_locked(page_addr);
    }
    buddy_unlock_if_needed(locked, flags);
}

/*
 * Fonctions helper pour allocation simplifiée
 */
void* allocate_pages(uint32_t num_pages)
{
    return buddy_alloc(num_pages);
}


void free_pages(void* page_addr, uint32_t num_pages)
{
    (void) num_pages;

    if (!page_addr) {
        return;
    }

    buddy_free(page_addr);

    return;

}

uint32_t get_free_page_count(void)
{
    return phys_alloc.free_pages;
}

uint32_t get_total_page_count(void)
{
    return phys_alloc.total_pages;
}

uint32_t get_allocated_page_count(void)
{
    return phys_alloc.pages_allocated;
}

uint32_t get_freed_page_count(void)
{
    return phys_alloc.pages_freed;
}

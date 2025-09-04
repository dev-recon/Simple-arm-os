/* kernel/memory/physical.c - Corrige pour eviter conflits avec MMU */
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>


physical_allocator_t phys_alloc;

static buddy_block_t* free_lists[MAX_ORDER + 1];
uint32_t buddy_base = 0;
struct page_info *page_infos;

/* Forward declarations des fonctions statiques */
static int set_page_used(uint32_t page_index);
static void set_page_free(uint32_t page_index);
static bool is_page_free(uint32_t page_index);
static void reserve_kernel_pages(void);
static void reserve_bitmap_pages(void);
static void reserve_heap_pages(void);
static void reserve_dtb_pages(void);
//static void reserve_mmu_pages(void);

void* early_alloc(uint32_t size, uint32_t align) {
    // Aligner l’adresse de départ
    uint32_t alloc_base = ALIGN_UP(buddy_base, align);

    // Avancer le pointeur
    buddy_base = ALIGN_UP(alloc_base + size, PAGE_SIZE);

    return (void*)alloc_base;
}

void buddy_init()
{

    uint32_t page_info_size = phys_alloc.free_pages * sizeof(struct page_info);

    // Trouve une région libre juste après le kernel (et DTB)
    void* page_info_region = early_alloc(page_info_size,8);
    void* page_info_ = (void* )ALIGN_UP((uint32_t)page_info_region,8);

    // Zéro-initialise
    memset(page_info_, 0, page_info_size);

    page_infos = (struct page_info*)page_info_;

    for (int i = 0; i <= MAX_ORDER; i++) {
        free_lists[i] = NULL;
    }

    buddy_base = ALIGN_UP(BUDDY_BASE,PAGE_SIZE);

    // Toute la mémoire est d'abord un seul gros bloc
    buddy_block_t* block = (buddy_block_t*)buddy_base;
    block->next = NULL;
    free_lists[MAX_ORDER] = block;
    uint32_t mem_size = detect_memory();
    uint32_t ram_end = VIRT_RAM_START + mem_size;
    uint32_t buddy_pages = (ram_end - buddy_base) / PAGE_SIZE;

    kprintf("[MEM] Buddy Allocator configuration:\n");
    kprintf("[MEM]   Buddy Base : 0x%08X\n", buddy_base);
    kprintf("[MEM]   RAM End: 0x%08X\n", ram_end);
    kprintf("[MEM]   Buddy Size: %u\n", ram_end - buddy_base);
    kprintf("[MEM]   Buddy pages: %u\n", buddy_pages);

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

    uint32_t ram_end = VIRT_RAM_START + get_kernel_memory_size();
    uint32_t max_pages = (ram_end - buddy_base) / PAGE_SIZE;

    //kprintf("\n***********************************************************************\n");
    //kprintf("\n***********************************************************************\n");
    //kprintf("Allocation requested for %u pages\n", num_block);

    size_t index = 0;

    while (index < max_pages ) {
        bool ok = true;

        for (size_t j = 0; j < num_block; ++j) {
            if (page_infos[index + j].used || page_infos[index + j].reserved) {
                ok = false;
                break;
            }
        }

        if (!ok) {
            index += page_infos[index].size;
            continue;
        }

        uint32_t addr = buddy_base + index * PAGE_SIZE;

        // Marque les pages comme utilisées
        for (size_t j = 0; j < num_block; ++j) {
            page_infos[index + j].used = 1;
            page_infos[index + j].start = addr;
            page_infos[index + j].size = num_block;    
        }

        memset((void *)addr, 0, num_block * PAGE_SIZE);
        //kprintf("Found block at 0x%08X\n", addr);
        //kprintf("page_infos[%d].used = %u\n", index, page_infos[index].used);
        //kprintf("page_infos[%d].start = 0x%08X\n", index, page_infos[index].start);
        //kprintf("page_infos[%d].size = %u\n", index, page_infos[index].size); 

        return (void*)addr;
    }

    return NULL; // Aucun bloc disponible
}

void buddy_free(void* ptr) {
    uint32_t addr = (uint32_t)ptr;
    size_t index = (addr - buddy_base) / PAGE_SIZE;
    uint32_t ram_end = VIRT_RAM_START + get_kernel_memory_size();
    uint32_t max_pages = (ram_end - buddy_base) / PAGE_SIZE;

    //kprintf("\n***********************************************************************\n");
    //kprintf("\n***********************************************************************\n");
    //kprintf("Free requested for 0x%08X\n", addr);
    //kprintf("Size to be freed %u at index %u\n", page_infos[index].size, index);

    size_t block_size = page_infos[index].size;
    if (block_size == 0 || block_size > max_pages) {
        kprintf("[ERROR] buddy_free: Invalid size=%d at index %u\n", block_size, index);
        return;
    }

    uint32_t start_addr = page_infos[index].start;
    if (start_addr != addr) {
        index = (start_addr - buddy_base) / PAGE_SIZE;
        //kprintf("PTR is not at the start of the allocated region\n");
        //kprintf("Real start at 0x%08X\n", start_addr);
        //kprintf("Size to be freed %u at index %u\n", page_infos[index].size, index);
    }

    for (size_t i = 0; i < block_size; ++i) {
        page_infos[index + i].used = 0;
        page_infos[index + i].size = 0;
    }

    page_infos[index].start = 0;
    page_infos[index].size = 0;  
}

#if(0)
void* buddy_alloc2(size_t size)
{
    int order = get_order(size);
    int current = order;

    while (current <= MAX_ORDER && !free_lists[current]) {
        current++;
    }

    if (current > MAX_ORDER)
        return NULL;

    // Split until desired order
    while (current > order) {
        buddy_block_t* block = free_lists[current];
        free_lists[current] = block->next;

        current--;
        uintptr_t buddy_addr = (uintptr_t)block + (1 << (current + 12));
        buddy_block_t* buddy = (buddy_block_t*)buddy_addr;
        buddy->next = NULL;

        block->next = NULL;
        free_lists[current] = block;
        free_lists[current]->next = buddy;
    }

    buddy_block_t* block = free_lists[order];
    free_lists[order] = block->next;

    uint32_t index = ((uint32_t)block - buddy_base) >> 12;

    for (int i = 0; i < (1 << order); i++) {
        page_infos[index + i].used = 1;

        if (i == 0) {
            page_infos[index + i].order = order;  // Premier du bloc
        } else {
            page_infos[index + i].order = -1;     // Marqueur = bloc secondaire
        }
    }

    return (void*)block;
}


void buddy_free2(void* ptr, size_t size)
{
    int order = get_order(size);
    uintptr_t addr = (uintptr_t)ptr;

    while (order < MAX_ORDER) {
        uintptr_t buddy_addr = buddy_of(addr, order);
        buddy_block_t* prev = NULL;
        buddy_block_t* curr = free_lists[order];

        // Recherche du buddy
        while (curr) {
            if ((uintptr_t)curr == buddy_addr)
                break;
            prev = curr;
            curr = curr->next;
        }

        if (!curr)
            break;

        // Fusion
        if (prev)
            prev->next = curr->next;
        else
            free_lists[order] = curr->next;

        addr = addr < buddy_addr ? addr : buddy_addr;
        order++;
    }

    buddy_block_t* block = (buddy_block_t*)addr;
    block->next = free_lists[order];
    free_lists[order] = block;
    uint32_t index = ((uint32_t)block - buddy_base) >> 12;

    int order2 = page_infos[index].order;

    if (order2 < 0 || !page_infos[index].used) {
        panic("Invalid free()");
    }

    if (order2 != order) {
        panic("Invalid free() - Order mismatch");
    }

    // On libère toutes les pages du bloc
    for (int i = 0; i < (1 << order); i++) {
        page_infos[index + i].used = 0;
        page_infos[index + i].order = 0;
    }
}
#endif

bool init_memory(void)
{
    uint32_t mem_start = VIRT_RAM_START;
    //uint32_t mem_size = detect_memory();    // UNCOMMENT FOR PROD

    // GDB DEBUG BLOCK - COMMENT FOR PROD
    dtb_address = 0x48000000;
    uint32_t mem_size = 2 * 1024 * 1024 * 1024u;  // 2GB total (0-2GB)
    kernel_memory_size = mem_size ;  // FIX IT - For use of GDB
    // END GDB DEBUG BLOCK - COMMENT FOR PROD

    uint32_t bitmap_size_words;
    uint32_t bitmap_size_bytes;
    uint32_t i;

    /* NOUVEAU: Exclure la zone heap de la RAM allouable */
    extern uint8_t* heap_base;
    extern size_t heap_size;
    
    uint32_t heap_start = (uint32_t)heap_base;
    uint32_t heap_end = heap_start + heap_size;
    
    /* Si le heap est dans la RAM detectee, reduire la RAM allouable */
    if (heap_start >= mem_start && heap_start < mem_start + mem_size) {
        KINFO("[MEM] Heap detected in RAM zone, adjusting...\n");
        KINFO("[MEM]   Original RAM: 0x%08X - 0x%08X\n", mem_start, mem_start + mem_size);
        KINFO("[MEM]   Heap zone:    0x%08X - 0x%08X\n", heap_start, heap_end);
        
        /* Utiliser seulement la RAM avant le heap */
        mem_size = heap_start - mem_start;
        
        KINFO("[MEM]   Adjusted RAM: 0x%08X - 0x%08X (%u MB)\n", 
              mem_start, mem_start + mem_size, mem_size / (1024*1024));
    }

    
    kprintf("[MEM] Initializing physical memory allocator...\n");
    kprintf("[MEM] RAM: 0x%08X - 0x%08X (%u MB)\n", 
            mem_start, mem_start + mem_size, mem_size / (1024*1024));

    uint32_t bitmap_start = mem_start;
    
    phys_alloc.start_addr = bitmap_start + (phys_alloc.bitmap_pages * PAGE_SIZE);;
    phys_alloc.total_pages = mem_size / PAGE_SIZE;
    
    /* Bitmap: 1 bit per page */
    bitmap_size_words = (phys_alloc.total_pages + 31) / 32;
    bitmap_size_bytes = bitmap_size_words * 4;
    phys_alloc.bitmap_pages = (bitmap_size_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    
    /* Placer le bitmap APReS le kernel et heap, pas a la fin de la RAM */
    //extern uint32_t __free_memory_start;

    phys_alloc.bitmap = (uint32_t*)bitmap_start;
    
    kprintf("[MEM] Bitmap configuration:\n");
    kprintf("[MEM]   Total pages: %u\n", phys_alloc.total_pages);
    kprintf("[MEM]   Bitmap words: %u\n", bitmap_size_words);
    kprintf("[MEM]   Bitmap bytes: %u\n", bitmap_size_bytes);
    kprintf("[MEM]   Bitmap pages: %u\n", phys_alloc.bitmap_pages);
    kprintf("[MEM]   Bitmap address: 0x%08X\n", (uint32_t)phys_alloc.bitmap);
    
    /* Verifier que le bitmap ne depasse pas la RAM */
    if ((uint32_t)phys_alloc.bitmap + bitmap_size_bytes > mem_start + mem_size) {
        kprintf("[MEM] ERROR: Bitmap would extend beyond RAM!\n");
        return false;
    }
    
    /* Mark all pages as free initially */
    for (i = 0; i < bitmap_size_words; i++) {
        phys_alloc.bitmap[i] = 0;
    }
    
    phys_alloc.free_pages = phys_alloc.total_pages;
    
    kprintf("[MEM] Initial state: %u pages (%u MB) free\n", 
            phys_alloc.free_pages, 
            (phys_alloc.free_pages * PAGE_SIZE) / (1024*1024));

    
    /* Reserve kernel pages */
    reserve_kernel_pages();
    
    /* Reserve bitmap pages */
    reserve_bitmap_pages();
        
    init_kernel_heap();

    reserve_heap_pages();

    reserve_dtb_pages();

    //reserve_mmu_pages();

    kprintf("[MEM] Final state: %u pages (%u MB) free\n", 
        phys_alloc.free_pages, 
        (phys_alloc.free_pages * PAGE_SIZE) / (1024*1024));

    buddy_init();
    
    return true;
}

static void reserve_kernel_pages(void)
{
    kprintf("[MEM] Reserving kernel pages...\n");
    
    /* Utiliser les symboles du linker script */
    extern uint32_t __start;
    extern uint32_t __end;
    extern uint32_t __kernel_size;
    extern uint32_t __text_start, __text_end;
    extern uint32_t __data_start, __data_end;
    extern uint32_t __bss_start, __bss_end;
    
    uint32_t kernel_start = (uint32_t)&__start;
    uint32_t kernel_end = (uint32_t)&__end;
    uint32_t kernel_size = (uint32_t)&__kernel_size;
    
    kprintf("[MEM] Kernel layout from linker:\n");
    kprintf("[MEM]   Kernel start:  0x%08X\n", kernel_start);
    kprintf("[MEM]   Kernel end:    0x%08X\n", kernel_end);
    kprintf("[MEM]   Kernel size:   %u bytes (%u KB)\n", kernel_size, kernel_size / 1024);
    
    /* Afficher les sections detaillees */
    kprintf("[MEM] Kernel sections:\n");
    kprintf("[MEM]   .text:  0x%08X - 0x%08X (%u bytes)\n", 
            (uint32_t)&__text_start, (uint32_t)&__text_end,
            (uint32_t)&__text_end - (uint32_t)&__text_start);
    kprintf("[MEM]   .data:  0x%08X - 0x%08X (%u bytes)\n", 
            (uint32_t)&__data_start, (uint32_t)&__data_end,
            (uint32_t)&__data_end - (uint32_t)&__data_start);
    kprintf("[MEM]   .bss:   0x%08X - 0x%08X (%u bytes)\n", 
            (uint32_t)&__bss_start, (uint32_t)&__bss_end,
            (uint32_t)&__bss_end - (uint32_t)&__bss_start);
    
    /* Verifications de securite */
    if (kernel_start < phys_alloc.start_addr) {
        kprintf("[MEM] ERROR: Kernel starts before RAM!\n");
        kprintf("[MEM]   Kernel: 0x%08X, RAM: 0x%08X\n", kernel_start, phys_alloc.start_addr);
        return;
    }
    
    uint32_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    if (kernel_end > ram_end) {
        kprintf("[MEM] ERROR: Kernel extends beyond RAM!\n");
        kprintf("[MEM]   Kernel end: 0x%08X, RAM end: 0x%08X\n", kernel_end, ram_end);
        return;
    }
    
    /* Reserver depuis le debut de la RAM jusqu'a la fin du kernel */
    uint32_t kernel_start_page = phys_alloc.start_addr;  /* Debut de la RAM */
    uint32_t kernel_end_page = ALIGN_UP(kernel_end, PAGE_SIZE);
    
    kprintf("[MEM] Reserving from start of RAM to end of kernel:\n");
    kprintf("[MEM]   Start page: 0x%08X\n", kernel_start_page);
    kprintf("[MEM]   End page:   0x%08X\n", kernel_end_page);
    
    /* Calculer le nombre de pages */
    uint32_t pages_to_reserve = (kernel_end_page - kernel_start_page) / PAGE_SIZE;
    kprintf("[MEM]   Pages to reserve: %u\n", pages_to_reserve);
    
    /* Reserver les pages */
    uint32_t pages_reserved = 0;
    uint32_t addr;
    
    for (addr = kernel_start_page; addr < kernel_end_page; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            kprintf("[MEM] ERROR: Page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    kprintf("[MEM] Kernel pages reserved: %u/%u\n", pages_reserved, pages_to_reserve);
}

static void reserve_dtb_pages(void)
{
    kprintf("[MEM] Reserving dtb pages...\n");
    
    /* Utiliser les symboles du linker script */
    extern uint32_t dtb_address;
    
    uint32_t dtb_start = dtb_address;
    uint32_t dtb_size = (uint32_t)0x100000;
    uint32_t dtb_end = (uint32_t)dtb_start + dtb_size;

    
    kprintf("[MEM] DTB layout from QEMU:\n");
    kprintf("[MEM]   DTB start:  0x%08X\n", dtb_start);
    kprintf("[MEM]   DTB end:    0x%08X\n", dtb_start + dtb_size);
    kprintf("[MEM]   DTB size:   %u bytes (%u KB)\n", dtb_size, dtb_size / 1024);
    
    /* Verifications de securite */
    if (dtb_start < phys_alloc.start_addr) {
        kprintf("[MEM] ERROR: DTB starts before RAM!\n");
        kprintf("[MEM]   DTB: 0x%08X, RAM: 0x%08X\n", dtb_start, phys_alloc.start_addr);
        return;
    }
    
    uint32_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    if (dtb_end > ram_end) {
        kprintf("[MEM] ERROR: Kernel extends beyond RAM!\n");
        kprintf("[MEM]   Kernel end: 0x%08X, RAM end: 0x%08X\n", dtb_end, ram_end);
        return;
    }
    
    /* Reserver depuis le debut de la RAM jusqu'a la fin du kernel */
    uint32_t dtb_start_page = dtb_start;  /* Debut de la DTB */
    uint32_t dtb_end_page = ALIGN_UP(dtb_end, PAGE_SIZE);
    buddy_base = ALIGN_UP(dtb_end_page + PAGE_SIZE, PAGE_SIZE) ; 
    
    kprintf("[MEM] Reserving from start of DTB to end of DTB:\n");
    kprintf("[MEM]   Start page: 0x%08X\n", dtb_start_page);
    kprintf("[MEM]   End page:   0x%08X\n", dtb_end_page);
    kprintf("[MEM]   buddy_base:   0x%08X\n", buddy_base);
    
    /* Calculer le nombre de pages */
    uint32_t pages_to_reserve = (dtb_end_page - dtb_start_page) / PAGE_SIZE;
    kprintf("[MEM]   Pages to reserve: %u\n", pages_to_reserve);
    
    /* Reserver les pages */
    uint32_t pages_reserved = 0;
    uint32_t addr;
    
    for (addr = dtb_start_page; addr < dtb_end_page; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            kprintf("[MEM] ERROR: Page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    kprintf("[MEM] DTB pages reserved: %u/%u\n", pages_reserved, pages_to_reserve);
}

#if(0)
static void reserve_mmu_pages(void)
{
    kprintf("[MEM] Reserving mmu pages...\n");
    
    /* Utiliser les symboles du linker script */
    extern uint32_t __mmu_tables_start;
    extern uint32_t __mmu_tables_end;
    extern uint32_t __mmu_size;

    uint32_t mmu_start = (uint32_t)&__mmu_tables_start;
    uint32_t mmu_end = (uint32_t)&__mmu_tables_end;
    uint32_t mmu_size = (uint32_t)&__mmu_size;
    
    kprintf("[MEM] MMU Tables layout from linker:\n");
    kprintf("[MEM]   MMU start:  0x%08X\n", mmu_start);
    kprintf("[MEM]   MMU end:    0x%08X\n", mmu_end);
    kprintf("[MEM]   MMU size:   %u bytes (%u KB)\n", mmu_size, mmu_size / 1024);
    
    /* Afficher les sections detaillees */
    
    /* Verifications de securite */
    if (mmu_start < phys_alloc.start_addr) {
        kprintf("[MEM] ERROR: MMU Tables starts before RAM!\n");
        kprintf("[MEM]   MMU Tables start: 0x%08X, RAM: 0x%08X\n", mmu_start, phys_alloc.start_addr);
        return;
    }
    
    uint32_t ram_end = phys_alloc.start_addr + phys_alloc.total_pages * PAGE_SIZE;
    if (mmu_end > ram_end) {
        kprintf("[MEM] ERROR: MMU Tables  extends beyond RAM!\n");
        kprintf("[MEM]   MMU Tables end: 0x%08X, RAM end: 0x%08X\n", mmu_end, ram_end);
        return;
    }
    
    /* Reserver depuis le debut de la RAM jusqu'a la fin du kernel */
    uint32_t mmu_start_page = mmu_start;  /* Debut de la RAM */
    uint32_t mmu_end_page = ALIGN_UP(mmu_end, PAGE_SIZE);
    
    kprintf("[MEM] Reserving MMU TABLES PAGES:\n");
    kprintf("[MEM]   Start page: 0x%08X\n", mmu_start_page);
    kprintf("[MEM]   End page:   0x%08X\n", mmu_end_page);
    
    /* Calculer le nombre de pages */
    uint32_t pages_to_reserve = (mmu_end_page - mmu_start_page) / PAGE_SIZE;
    kprintf("[MEM]   Pages to reserve: %u\n", pages_to_reserve);
    
    /* Reserver les pages */
    uint32_t pages_reserved = 0;
    uint32_t addr;
    
    for (addr = mmu_start_page; addr < mmu_end_page; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            kprintf("[MEM] ERROR: Page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    kprintf("[MEM] MMU Tables pages reserved: %u/%u\n", pages_reserved, pages_to_reserve);
}

#endif

static void reserve_bitmap_pages(void)
{
    kprintf("[MEM] Reserving bitmap pages...\n");
    
    uint32_t bitmap_start = (uint32_t)phys_alloc.bitmap;
    uint32_t bitmap_end = bitmap_start + (phys_alloc.bitmap_pages * PAGE_SIZE);
    
    kprintf("[MEM] Bitmap region: 0x%08X - 0x%08X (%u pages)\n",
            bitmap_start, bitmap_end, phys_alloc.bitmap_pages);
    
    uint32_t pages_reserved = 0;
    uint32_t addr;
    
    for (addr = bitmap_start; addr < bitmap_end; addr += PAGE_SIZE) {
        uint32_t page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
        
        if (page_index >= phys_alloc.total_pages) {
            kprintf("[MEM] ERROR: Bitmap page index %u out of range!\n", page_index);
            break;
        }
        
        if (set_page_used(page_index)) {
            pages_reserved++;
        }
    }
    
    kprintf("[MEM] Bitmap pages reserved: %u/%u\n", pages_reserved, phys_alloc.bitmap_pages);
}

static void reserve_heap_pages(void)
{
    extern uint8_t* heap_base;
    extern size_t heap_size;
    
    if (!heap_base || heap_size == 0) {
        KWARN("[MEM] Heap not initialized, skipping reservation\n");
        return;
    }
    
    uint32_t heap_start = (uint32_t)heap_base;
    uint32_t heap_end = heap_start + heap_size;
    
    KINFO("[MEM] === HEAP RESERVATION ===\n");
    KINFO("[MEM]   Heap start: 0x%08X\n", heap_start);
    KINFO("[MEM]   Heap end:   0x%08X\n", heap_end);
    KINFO("[MEM]   Heap size:  %u MB\n", heap_size / (1024*1024));
    
    uint32_t reserved_count = 0;
    for (uint32_t addr = heap_start; addr < heap_end; addr += PAGE_SIZE) {
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
    //kprintf("[MEM] INFO: is page free index %d\n",page_index);
    return !(phys_alloc.bitmap[word_index] & (1 << bit_index));
}


void* allocate_physical_page(void)
{
    return buddy_alloc(1);
}

void free_physical_page(void* page_addr)
{
    buddy_free(page_addr);
}

void free_physical_page2(void* page_addr)
{
    uint32_t addr = (uint32_t)page_addr;
    uint32_t page_index;
    
    if (addr % PAGE_SIZE != 0) {
        KWARN("[MEM] WARNING: free_physical_page with unaligned address 0x%08X\n", addr);
        return;
    }
    
    if (addr < phys_alloc.start_addr || addr >= phys_alloc.start_addr + (phys_alloc.total_pages * PAGE_SIZE)) {
        KWARN("[MEM] WARNING: free_physical_page with invalid address 0x%08X\n", addr);
        return;
    }
    
    page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
    set_page_free(page_index);
}

/*
 * Fonctions helper pour allocation simplifiée
 */
void* allocate_kernel_pages(uint32_t num_pages)
{
    return allocate_contiguous_pages(num_pages, true);
}

void* allocate_user_pages(uint32_t num_pages) 
{
    return allocate_contiguous_pages(num_pages, false);
}

/*
 * Pour l'allocation de pages individuelles
 */
void* allocate_kernel_page(void)
{
    return allocate_kernel_pages(1);
}

void* allocate_user_page(void)
{
    return allocate_user_pages(1);
}

void* allocate_contiguous_pages(uint32_t num_pages, bool kernel_space)
{
    (void) kernel_space;
    //uint32_t order = get_order(num_pages);
    return buddy_alloc(num_pages);
}


void free_contiguous_pages(void* page_addr, uint32_t num_pages)
{
    (void) num_pages;

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
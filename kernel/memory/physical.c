/* kernel/memory/physical.c - Corrige pour eviter conflits avec MMU */
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>


physical_allocator_t phys_alloc;

/* Forward declarations des fonctions statiques */
static int set_page_used(uint32_t page_index);
static void set_page_free(uint32_t page_index);
static bool is_page_free(uint32_t page_index);
static void reserve_kernel_pages(void);
static void reserve_bitmap_pages(void);
static void reserve_heap_pages(void);

bool init_memory(void)
{
    uint32_t mem_start = VIRT_RAM_START;
    uint32_t mem_size = detect_memory();
    //uint32_t mem_start = 0x00000000;        // ← Commencer à 0 au lieu de 0x40000000
    //uint32_t mem_size = 3 * 1024 * 1024 * 1024u;  // 2GB total (0-2GB)


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
    
    kprintf("[MEM] Final state: %u pages (%u MB) free\n", 
            phys_alloc.free_pages, 
            (phys_alloc.free_pages * PAGE_SIZE) / (1024*1024));
    
    init_kernel_heap();

    reserve_heap_pages();
    
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
    uint32_t i;
    uint32_t phys_addr;
    
    if (phys_alloc.free_pages == 0) {
        kprintf("[MEM] WARNING: No free pages available!\n");
        return NULL;
    }
    
    for (i = 0; i < phys_alloc.total_pages; i++) {
        if (is_page_free(i)) {
            set_page_used(i);
            
            phys_addr = phys_alloc.start_addr + (i * PAGE_SIZE);
            memset((void*)phys_addr, 0, PAGE_SIZE);
            
            return (void*)phys_addr;
        }
    }
    
    kprintf("[MEM] ERROR: Could not find free page despite free_pages=%u!\n", phys_alloc.free_pages);
    return NULL;
}

void free_physical_page(void* page_addr)
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


void* allocate_contiguous_pages2(uint32_t num_pages, bool kernel_space)
{
    uint32_t consecutive = 0;
    uint32_t start_page = 0;
    uint32_t i;
    uint32_t j;
    uint32_t phys_addr;
    uint32_t search_start = 0;
    uint32_t search_end = phys_alloc.total_pages;

    KDEBUG("[MEM] Allocating %u contiguous pages (kernel_space=%s)...\n", 
           num_pages, kernel_space ? "true" : "false");

    if (phys_alloc.free_pages < num_pages) {
        KERROR("[MEM] ERROR: Not enough free pages (%u available, %u requested)\n", 
                phys_alloc.free_pages, num_pages);
        return NULL;
    }

    /*
     * IMPORTANT: Avec QEMU virt, TOUTE la RAM physique commence à 0x40000000
     * Il n'y a PAS de RAM physique < 0x40000000
     * 
     * La distinction kernel/user se fait au niveau VIRTUEL :
     * - Kernel virtual : 0x40000000+ (TTBR1) → RAM physique 0x40000000+
     * - User virtual   : 0x00000000+ (TTBR0) → RAM physique 0x40000000+ (même RAM!)
     * 
     * L'allocateur physique alloue dans la même RAM pour les deux cas.
     * La différence est dans le mapping virtuel fait par la MMU.
     */

    /* 
     * Stratégie d'allocation dans la RAM physique unique (0x40000000+) :
     * - Kernel : préfère les adresses hautes (moins de fragmentation)
     * - User   : préfère les adresses basses (pour éviter les conflits kernel)
     */
    
    if (kernel_space) {
        /*
         * Allocation kernel : recherche depuis la fin vers le début
         * Cela évite de fragmenter l'espace user en bas de la RAM
         */
        KDEBUG("[MEM] Kernel allocation: searching from high addresses\n");
        
        /* Recherche en ordre inverse pour le kernel */
        for (i = search_end; i > 0; i--) {
            uint32_t page_idx = i - 1;
            
            if (is_page_free(page_idx)) {
                if (consecutive == 0) {
                    start_page = page_idx;
                }
                consecutive++;
                
                if (consecutive == num_pages) {
                    /* Ajuster start_page pour pointer vers le début du bloc */
                    start_page = page_idx;
                    
                    /* Marquer les pages comme utilisées */
                    for (j = start_page; j < start_page + num_pages; j++) {
                        set_page_used(j);
                    }
                    
                    phys_addr = phys_alloc.start_addr + (start_page * PAGE_SIZE);
                    memset((void*)phys_addr, 0, num_pages * PAGE_SIZE);
                    
                    KDEBUG("[MEM] Allocated %u kernel pages at 0x%08X\n", 
                           num_pages, phys_addr);
                    return (void*)phys_addr;
                }
            } else {
                consecutive = 0;
            }
        }
        
    } else {
        /*
         * Allocation user : recherche depuis le début
         * Utilise les adresses basses de la RAM physique
         */
        KDEBUG("[MEM] User allocation: searching from low addresses\n");
        
        /* Éviter la zone kernel réservée (premiers X MB) */
        extern uint32_t __end;
        uint32_t kernel_end_addr = (uint32_t)&__end;
        uint32_t kernel_reserved_pages = ((kernel_end_addr - phys_alloc.start_addr) / PAGE_SIZE) + 256; /* +1MB sécurité */
        
        if (kernel_reserved_pages < search_start) {
            search_start = kernel_reserved_pages;
        }
        
        KDEBUG("[MEM] User search starts after kernel zone at page %u (0x%08X)\n",
               search_start, phys_alloc.start_addr + (search_start * PAGE_SIZE));

        KDEBUG("[MEM] Free Pages %u\n",phys_alloc.free_pages);

        
        /* Recherche normale pour l'userspace */
        for (i = search_start; i < search_end; i++) {
            if (is_page_free(i)) {
                if (consecutive == 0) {
                    start_page = i;
                }
                consecutive++;
                
                if (consecutive == num_pages) {
                    /* Marquer les pages comme utilisées */
                    for (j = start_page; j < start_page + num_pages; j++) {
                        set_page_used(j);
                    }
                    
                    phys_addr = phys_alloc.start_addr + (start_page * PAGE_SIZE);
                    memset((void*)phys_addr, 0, num_pages * PAGE_SIZE);
                    
                    KDEBUG("[MEM] Allocated %u user pages at 0x%08X\n", 
                           num_pages, phys_addr);
                    return (void*)phys_addr;
                }
            } else {
                consecutive = 0;
            }
        }
    }
    
    KERROR("[MEM] ERROR: Could not find %u contiguous pages for %s\n", 
           num_pages, kernel_space ? "kernel" : "user");
    return NULL;
}

void* do_physical_allocation(uint32_t num_pages, bool kernel_space)
{
    (void) kernel_space;
    uint32_t consecutive = 0;
    uint32_t start_page = 0;
    uint32_t i;
    uint32_t j;
    uint32_t phys_addr;

    kprintf("[MEM] Allocating %u contiguous pages...\n", num_pages);

    if (phys_alloc.free_pages < num_pages) {
        KERROR("[MEM] ERROR: Not enough free pages (%u available, %u requested)\n", 
                phys_alloc.free_pages, num_pages);
        return NULL;
    }

#if(0)
    KDEBUG("=== FULL ALLOCATOR DEBUG ===\n");
    
    // 1. Adresses critiques
    KDEBUG("Code location:\n");
    KDEBUG("  allocate_contiguous_pages: 0x%08X\n", (uint32_t)allocate_contiguous_pages);
    KDEBUG("  Current PC: ");
    uint32_t pc;
    __asm__ volatile("mov %0, pc" : "=r"(pc));
    KDEBUG("0x%08X\n", pc);
    
    // 2. Structures de données
    KDEBUG("Data structures:\n");
    KDEBUG("  phys_alloc struct: 0x%08X\n", (uint32_t)&phys_alloc);
    KDEBUG("  phys_alloc.bitmap: 0x%08X\n", (uint32_t)phys_alloc.bitmap);
    
    // 3. Pile actuelle
    uint32_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    KDEBUG("  Current SP: 0x%08X\n", sp);
    
    // 4. Contexte MMU
    uint32_t ttbr0, ttbr1, ttbcr;
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr0));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 1" : "=r"(ttbr1));
    __asm__ volatile("mrc p15, 0, %0, c2, c0, 2" : "=r"(ttbcr));
    
    KDEBUG("MMU state:\n");
    KDEBUG("  TTBR0: 0x%08X\n", ttbr0 & ~0x7F);
    KDEBUG("  TTBR1: 0x%08X\n", ttbr1 & ~0x7F);
    KDEBUG("  TTBCR: 0x%08X\n", ttbcr);
    
    // 5. Test d'accès aux données critiques
    KDEBUG("Access tests:\n");
    
    __asm__ volatile("" ::: "memory");  // Barrier
    uint32_t test1 = phys_alloc.total_pages;
    KDEBUG("  phys_alloc.total_pages: %u\n", test1);
    
    __asm__ volatile("" ::: "memory");  // Barrier
    uint32_t test2 = phys_alloc.bitmap[0];
    KDEBUG("  phys_alloc.bitmap[0]: 0x%08X\n", test2);
    
    KDEBUG("=== END ALLOCATOR DEBUG ===\n");
#endif

    for (i = 0; i < phys_alloc.total_pages; i++) {
        //KDEBUG("[MEM]: searching free page at i=%d\n",i);
        bool page_free = is_page_free(i);
        if (page_free) {
            //KDEBUG("[MEM]: Found free page at i=%d\n",i);
            if (consecutive == 0) {
                start_page = i;
            }
            consecutive++;

            //KDEBUG("[MEM]: Found free page at 0x%08X\n", phys_alloc.start_addr + (start_page * PAGE_SIZE));
            
            if (consecutive == num_pages) {
                for (j = start_page; j < start_page + num_pages; j++) {
                    set_page_used(j);
                }
                
                phys_addr = phys_alloc.start_addr + (start_page * PAGE_SIZE);
                memset((void*)phys_addr, 0, num_pages * PAGE_SIZE);
                
                //kprintf("[MEM] Allocated %u pages at 0x%08X\n", num_pages, phys_addr);
                return (void*)phys_addr;
            }
        } else {
            consecutive = 0;
        }
    }
    
    KERROR("[MEM] ERROR: Could not find %u contiguous pages\n", num_pages);
    return NULL;
}


void* allocate_contiguous_pages(uint32_t num_pages, bool kernel_space)
{
        // Sauvegarder le contexte MMU actuel
    //uint32_t old_ttbr0 = get_ttbr0();
    //__asm__ volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(old_ttbr0));
    
    // Temporairement utiliser TTBR0 du kernel pour l'allocation
    //uint32_t kernel_ttbr0 = (uint32_t)get_kernel_ttbr0();
    //set_ttbr0(kernel_ttbr0);

    // Faire l'allocation avec accès complet aux structures kernel
    void* result = do_physical_allocation(num_pages, kernel_space);

    //set_ttbr0(old_ttbr0);
    
    return result;
}

void do_free_contiguous_pages(void* page_addr, uint32_t num_pages)
{
    uint32_t addr = (uint32_t)page_addr;
    uint32_t start_page_index;
    uint32_t i;
    
    if (addr % PAGE_SIZE != 0) {
        KWARN("[MEM] WARNING: free_contiguous_pages with unaligned address 0x%08X\n", addr);
        return;
    }
    
    if (addr < phys_alloc.start_addr || addr >= phys_alloc.start_addr + (phys_alloc.total_pages * PAGE_SIZE)) {
        KWARN("[MEM] WARNING: free_contiguous_pages with invalid address 0x%08X\n", addr);
        return;
    }
    
    start_page_index = (addr - phys_alloc.start_addr) / PAGE_SIZE;
    
    //kprintf("[MEM] Freeing %u contiguous pages at 0x%08X\n", num_pages, addr);
    
    for (i = 0; i < num_pages; i++) {
        if (start_page_index + i < phys_alloc.total_pages) {
            set_page_free(start_page_index + i);
        }
    }
}

void free_contiguous_pages(void* page_addr, uint32_t num_pages)
{
            // Sauvegarder le contexte MMU actuel
    //uint32_t old_ttbr0 = get_ttbr0();
    
    // Temporairement utiliser TTBR0 du kernel pour l'allocation
    //uint32_t kernel_ttbr0 = (uint32_t)get_kernel_ttbr0();
    //set_ttbr0(kernel_ttbr0);

    // Faire l'allocation avec accès complet aux structures kernel
    do_free_contiguous_pages(page_addr, num_pages);

    //set_ttbr0(old_ttbr0);

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
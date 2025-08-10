#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

typedef struct __attribute__((aligned(8))) {
    uint32_t magic_start;
    size_t size;
    uint32_t magic_end;
} alloc_header_t;

#define ALLOC_MAGIC_START   0xDEADBEEF
#define ALLOC_MAGIC_END     0xCAFEBABE
#define FREED_MAGIC         0xDEADDEAD

uint8_t* heap_base = NULL;      /* Pointeur vers le debut du heap */
size_t heap_size = 0;           /* Taille totale du heap */
static bool heap_initialized = false;  /* etat d'initialisation */

//static uint32_t heap_offset = 0;

typedef struct free_block {
    size_t size;
    struct free_block* next;
} free_block_t;

free_block_t* free_list = NULL;

void init_kernel_heap(void)
{
    extern uint32_t __heap_start, __heap_size;
    
    /* Obtenir les infos du linker */
    heap_base = (uint8_t*)ALIGN_UP((uintptr_t)&__heap_start, 8);
    heap_size = (size_t)&__heap_size;
    
    kprintf("=== HEAP INITIALIZATION WITH GLOBALS ===\n");
    kprintf("Heap configuration:\n");
    kprintf("  Base address: %p\n", heap_base);
    kprintf("  Size:         %u MB (%u bytes)\n", 
            heap_size / (1024*1024), heap_size);
    
    /* Verifications */
    if (!heap_base || heap_size < (64 * 1024)) {
        panic("Invalid heap configuration");
    }
    
    /* Effacer la zone */
    memset(heap_base, 0, heap_size);
    
    /* Initialiser le premier bloc libre */
    free_block_t* initial_block = (free_block_t*)heap_base;
    initial_block->size = heap_size - sizeof(free_block_t);
    initial_block->next = NULL;
    
    /* Configurer les globales */
    free_list = initial_block;
    heap_initialized = true;
    
    kprintf("Heap ready: %u bytes available\n", initial_block->size);
}


void* kmalloc(size_t size)
{
    if (!heap_initialized || size == 0) return NULL;

    size = ALIGN_UP(size, 8);
    size_t total_size = sizeof(alloc_header_t) + size;
    
    free_block_t* prev = NULL;
    free_block_t* current = free_list;

    if (((uintptr_t)current & 0x7) != 0) {
        kprintf("KO kmalloc() misaligned: %p\n", current);
    }

    while (current) {
        if (current->size >= total_size) {
            // Split the block if large enough
            if (current->size >= total_size + sizeof(free_block_t) + 8) {
                free_block_t* new_block = (free_block_t*)((uint8_t*)current + total_size);
                new_block->size = current->size - total_size;
                new_block->next = current->next;
                current->next = NULL;
                current->size = total_size;

                if (prev) prev->next = new_block;
                else free_list = new_block;
            } else {
                // Use the full block
                if (prev) prev->next = current->next;
                else free_list = current->next;
            }

            // Setup allocation header
            alloc_header_t* header = (alloc_header_t*)current;
            header->magic_start = ALLOC_MAGIC_START;
            header->size = size;
            header->magic_end = ALLOC_MAGIC_END;

            void* raw_ptr = (uint8_t*)header + sizeof(alloc_header_t);
            void* aligned_ptr = (void*)ALIGN_UP((uintptr_t)raw_ptr, 8);

            // Corrige le header si l’alignement a pousse plus loin (peu probable si header deja aligne)
            size_t padding = (uint8_t*)aligned_ptr - (uint8_t*)raw_ptr;
            if (padding != 0) {
                // Impossible dans ton alloc actuel sans deplacer header, donc on peut juste assert ici
                kprintf("KO kmalloc(): alignment padding detected, allocator not designed for this!\n");
            }

            return aligned_ptr;
        }

        prev = current;
        current = current->next;
    }

    return NULL; // Out of memory
}


void kfree(void* ptr)
{
    if (!ptr || !heap_initialized) return;

    alloc_header_t* header = (alloc_header_t*)((uint8_t*)ptr - sizeof(alloc_header_t));

    // Verifier les canaries
    if (header->magic_start != ALLOC_MAGIC_START || header->magic_end != ALLOC_MAGIC_END) {
        kprintf("KO kfree(): canary corruption at %p!\n", ptr);
        return;
    }

    size_t total_size = sizeof(alloc_header_t) + ALIGN_UP(header->size, 8);
    free_block_t* block = (free_block_t*)header;
    block->size = total_size;
    block->next = NULL;

    // Fusion simple avec la liste (inserer trie pour fusion possible)
    free_block_t* prev = NULL;
    free_block_t* current = free_list;

    while (current && current < block) {
        prev = current;
        current = current->next;
    }

    // Fusion avec le bloc suivant
    if (current && (uint8_t*)block + block->size == (uint8_t*)current) {
        block->size += current->size;
        block->next = current->next;
    } else {
        block->next = current;
    }

    // Fusion avec le bloc precedent
    if (prev && (uint8_t*)prev + prev->size == (uint8_t*)block) {
        prev->size += block->size;
        prev->next = block->next;
    } else {
        if (prev) prev->next = block;
        else free_list = block;
    }
}


void* kcalloc(size_t nmemb, size_t size)
{
    size_t total_size = nmemb * size;
    void* ptr = kmalloc(total_size);
    
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

void* krealloc(void* ptr, size_t size)
{
    void* new_ptr;
    
    if (!ptr) return kmalloc(size);
    if (size == 0) {
        kfree(ptr);
        return NULL;
    }
    
    new_ptr = kmalloc(size);
    if (new_ptr) {
        /* TODO: Copy old data (need to track block sizes) */
        kfree(ptr);
    }
    
    return new_ptr;
}

void kheap_stats(void)
{
    free_block_t* current = free_list;
    size_t total_free = 0;
    int count = 0;

    kprintf("================= KERNEL HEAP STATS ======================\n");


    while (current) {
        kprintf("Free block at %p - size: %u\n", current, (uint32_t)current->size);
        total_free += current->size;
        current = current->next;
        count++;
    }

    kprintf("Total free: %u bytes in %d blocks\n", (uint32_t)total_free, count);
}
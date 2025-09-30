#include <../include/stddef.h>
#include <../include/stdint.h>
#include <../include/stdio.h>

// Header de bloc mémoire
struct block_header {
    size_t size;                    // Taille du bloc (sans header)
    int free;                       // 1 = libre, 0 = alloué
    struct block_header *next;      // Bloc suivant
    struct block_header *prev;      // Bloc précédent
};

#define HEADER_SIZE sizeof(struct block_header)
#define ALIGN(size) (((size) + 7) & ~7)  // Alignement 8 bytes

// Variables globales
static struct block_header *heap_head = NULL;
static void *current_brk = NULL;
static void *heap_start = NULL;

void *malloc(size_t size);
struct block_header *find_free_block(size_t size);
struct block_header *extend_heap(size_t size);
void split_block(struct block_header *block, size_t size);
void merge_blocks(struct block_header *first, struct block_header *second);
struct block_header *allocate_block(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);

extern void *brk(void *addr);
extern void *sbrk(void *addr);

void *malloc(size_t size) {

    if (size == 0) return NULL;
    
    size = ALIGN(size);

    struct block_header *block = NULL;

    // Calculer la taille totale nécessaire
    size_t total_size = HEADER_SIZE + size;

    uint32_t left_size = (uint32_t)current_brk - (uint32_t)heap_start ;

    //printf("malloc: left size in current allocated heap %u bytes\n", left_size);


    //printf("malloc: current_brk 0x%08X \n", current_brk);
    //printf("malloc: heap_start 0x%08X \n", heap_start);
    //printf("malloc: heap_head 0x%08X \n", (uint32_t)heap_head);

    if(!heap_start && !current_brk)
    {
        current_brk = sbrk(0);
        heap_start = current_brk ;
        heap_head = heap_start ;

        //printf("malloc: current_brk 0x%08X \n", current_brk);
        
        // Pas de bloc libre, étendre le heap
        block = extend_heap(size);
        if (!block) return NULL;
        
        return (char*)block + HEADER_SIZE;
    }

    //printf("malloc: trying to find free block of size %u \n", size);
 
    // Chercher un bloc libre existant
    block = find_free_block(size);
    if (block) {
        block->free = 0;
        
        // Diviser le bloc si il est trop grand
        split_block(block, size);
        return (char*)block + HEADER_SIZE;
    }
    
    left_size = (uint32_t)current_brk - (uint32_t)heap_head ;

    //printf("malloc: left size in current allocated heap %u bytes\n", left_size);

    if(total_size > left_size)
    {
        // Pas de bloc libre, étendre le heap
        block = extend_heap(size);
        if (!block) return NULL;
    }
    else
    {
        block = allocate_block(size);
        if (!block) return NULL;
    }

    return (char*)block + HEADER_SIZE;
}

struct block_header *find_free_block(size_t size) {

    struct block_header *current = (struct block_header *)heap_start;

    while (current) {
        if (current->free && current->size >= size) {
            return current;
        }
        current = current->next;
    }

    return NULL;  // Aucun bloc libre trouvé
}

struct block_header *allocate_block(size_t size) {

    // Créer le nouveau bloc
    struct block_header *new_block = (struct block_header*)heap_head;
    new_block->size = size;
    new_block->free = 0;
    new_block->next = NULL;
    new_block->prev = NULL;
    
    // Lier à la liste existante
    if (heap_start != heap_head) {
        // Trouver le dernier bloc
        struct block_header *last = heap_start;
        while (last->next) {
            last = last->next;
        }
        
        last->next = new_block;
        new_block->prev = last;
    }

    //printf("Exiting  allocate_block: new_block at %p\n", new_block);
    uint32_t new_head = (uint32_t)new_block + size + HEADER_SIZE;
    heap_head = (struct block_header*)new_head;

    return new_block;
}


struct block_header *extend_heap(size_t size) {

    if(!size)
        return NULL;
    
    //printf("Extending heap by %d bytes\n", size);
   
    // Calculer la taille totale nécessaire
    size_t total_size = HEADER_SIZE + size;
    
    // Étendre le heap
    void *new_brk = sbrk(total_size+heap_start);
    //printf("Got new BRK at %p bytes\n", new_brk);

    if (new_brk == (void*)-1) {
        return NULL;  // Échec allocation
    }

    current_brk = new_brk;
    
    // Créer le nouveau bloc
    struct block_header *new_block = allocate_block( size);
    //printf("Exiting  extend_heap: new_block at %p\n", new_block);
    
    return new_block;
}


void split_block(struct block_header *block, size_t size) {
    // Si le bloc est assez grand pour être divisé
    if (block->size >= size + HEADER_SIZE + 8) {
        // Créer un nouveau bloc avec le reste
        struct block_header *new_block = 
            (struct block_header*)((char*)block + HEADER_SIZE + size);
            
        new_block->size = block->size - size - HEADER_SIZE;
        new_block->free = 1;
        new_block->next = block->next;
        new_block->prev = block;
        
        if (block->next) {
            block->next->prev = new_block;
        }
        
        block->next = new_block;
        block->size = size;
    }
}


void merge_blocks(struct block_header *first, struct block_header *second) {
    first->size += second->size + HEADER_SIZE;
    first->next = second->next;
    
    if (second->next) {
        second->next->prev = first;
    }
}

void free(void *ptr) {
    if (!ptr) return;
    
    // Récupérer le header
    struct block_header *block = 
        (struct block_header*)((char*)ptr - HEADER_SIZE);
    
    // Marquer comme libre
    block->free = 1;
    
    // Fusionner avec le bloc suivant si libre
    if (block->next && block->next->free) {
        merge_blocks(block, block->next);
    }
    
    // Fusionner avec le bloc précédent si libre
    if (block->prev && block->prev->free) {
        merge_blocks(block->prev, block);
    }
}

void *calloc(size_t count, size_t size) {
    size_t total = count * size;
    void *ptr = malloc(total);
    
    if (ptr) {
        // Initialiser à zéro
        char *p = (char*)ptr;
        for (size_t i = 0; i < total; i++) {
            p[i] = 0;
        }
    }
    
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    // Implémentation simple : malloc + copy + free
    void *new_ptr = malloc(size);
    if (!new_ptr) return NULL;
    
    // Copier les données (approximatif)
    struct block_header *old_block = 
        (struct block_header*)((char*)ptr - HEADER_SIZE);
    
    size_t copy_size = (old_block->size < size) ? old_block->size : size;
    for (size_t i = 0; i < copy_size; i++) {
        ((char*)new_ptr)[i] = ((char*)ptr)[i];
    }
    
    free(ptr);
    return new_ptr;
}






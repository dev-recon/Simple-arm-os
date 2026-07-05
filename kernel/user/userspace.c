/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/user/userspace.c
 * Layer: Kernel / user execution support
 *
 * Responsibilities:
 * - Prepare and validate transitions into user programs.
 * - Coordinate user mappings with process execution.
 *
 * Notes:
 * - ABI details must stay aligned with syscall and context-switch code.
 */

#include <kernel/kernel.h>
#include <kernel/types.h>
#include <asm/mmu.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>
#include <kernel/task.h>
#include <kernel/process.h>



/* === MACROS UTILITAIRES === */


bool is_valid_user_ptr(const void* ptr)
{
    return IS_USER_ADDR((vaddr_t)(uintptr_t)ptr);
}


/* Macros pour simplifier l'utilisation */
#define put_user(value, ptr) ({ \
    int __ret = -1; \
    if (is_valid_user_ptr(ptr)) { \
        *(ptr) = (value); \
        __ret = 0; \
    } \
    __ret; \
})

#define get_user(value, ptr) ({ \
    int __ret = -1; \
    if (is_valid_user_ptr(ptr)) { \
        (value) = *(ptr); \
        __ret = 0; \
    } \
    __ret; \
})

static inline pgdir_cpu_t user_pgdir_cpu_view(pgdir_t pgdir)
{
    vaddr_t addr = (vaddr_t)(uintptr_t)pgdir;

    if (virt_in_direct_map(addr))
        return (pgdir_cpu_t)pgdir;
    if (phys_in_direct_map((paddr_t)addr))
        return (pgdir_cpu_t)phys_to_virt((paddr_t)addr);

    return (pgdir_cpu_t)pgdir;
}

static inline void user_flush_page_table_entry(const void *entry)
{
    dc_clean_mva((void *)entry);
    data_sync_barrier_inner_shareable_write();
}

int unmap_user_page(pgdir_t pgdir, vaddr_t vaddr, uint32_t asid)
{
    uint32_t l1_index;
    uint32_t l2_index;
    l1_entry_t *l1_entry;
    l2_table_t l2_table;
    paddr_t l2_phys;

    if (!pgdir || vaddr >= get_split_boundary() || (vaddr & (PAGE_SIZE - 1))) {
        return -EINVAL;
    }

    l1_index = get_L1_index(vaddr);
    l2_index = L2_INDEX(vaddr);
    l1_entry = &user_pgdir_cpu_view(pgdir)[l1_index];

    if ((*l1_entry & 0x3) != 0x1) {
        return -EINVAL;
    }

    l2_phys = *l1_entry & 0xFFFFFC00;
    l2_table = (l2_table_t)phys_to_virt(l2_phys);
    if ((l2_table[l2_index] & 0x3) == 0) {
        return 0;
    }

    l2_table[l2_index] = 0;
    user_flush_page_table_entry(&l2_table[l2_index]);
    invalidate_tlb_page_asid(vaddr, asid);

    for (uint32_t i = 0; i < 256; i++) {
        if ((l2_table[i] & 0x3) != 0) {
            return 0;
        }
    }

    *l1_entry = 0;
    user_flush_page_table_entry(l1_entry);
    invalidate_tlb_page_asid(vaddr, asid);
    free_page((void*)l2_phys);
    return 0;
}

int strnlen_user(const char* user_str, int max_len)
{
    int len = 0;
    
    /* Simple implementation */
    while (len < max_len && user_str[len] != '\0') {
        len++;
    }
    
    return (len < max_len) ? len : -EFAULT;
}


bool is_valid_user_range(const void* ptr, size_t size)
{
    vaddr_t start = (vaddr_t)(uintptr_t)ptr;
    vaddr_t end = start + size;
    
    /* Verifier les pointeurs invalides */
    if (!ptr || size == 0) {
        return false;
    }
    
    /* Verifier le debordement arithmetique */
    if (end < start) {
        return false;  /* Overflow */
    }
    
    /* Verifier que le debut est dans l'espace utilisateur */
    if (!is_valid_user_ptr(ptr)) {
        return false;
    }
    
    /* Verifier que la fin est dans l'espace utilisateur */
    if (!is_valid_user_ptr((void*)(end - 1))) {
        return false;
    }
    
    /* Verifier que toute la plage est dans l'espace utilisateur */
    //if (start < USER_SPACE_START || end > USER_SPACE_END) {
    //    return false;
    //}
    
    return true;
}

static bool is_mapped_user_range(pgdir_t pgdir, const void *ptr, size_t size)
{
    vaddr_t start = (vaddr_t)(uintptr_t)ptr;
    vaddr_t end = start + size - 1;
    vaddr_t page = start & PAGE_MASK;
    vaddr_t last_page = end & PAGE_MASK;

    if (!pgdir || !is_valid_user_range(ptr, size)) {
        return false;
    }

    while (page <= last_page) {
        if (!get_physical_address(pgdir, page)) {
            return false;
        }

        if (page > 0xFFFFFFFFu - PAGE_SIZE) {
            break;
        }
        page += PAGE_SIZE;
    }

    return true;
}

static void note_kernel_resolved_user_fault(bool is_lazy)
{
    task_t *task = task_current_local();

    if (!task || task->type != TASK_TYPE_PROCESS)
        return;

    task->page_faults++;
    if (is_lazy)
        task->lazy_faults++;
    else
        task->stack_faults++;
}

static int fault_in_user_page(pgdir_t pgdir, vaddr_t page, bool is_write)
{
    if (get_physical_address(pgdir, page))
        return 0;

    /*
     * Some syscalls are the first kernel-side access to a valid but still
     * unmapped user page. Fault it in explicitly so copy_to/from_user follows
     * the same VM contract as a user-mode load/store fault.
     */
    if (handle_lazy_anon_fault(page, is_write) == 0 &&
        get_physical_address(pgdir, page)) {
        note_kernel_resolved_user_fault(true);
        return 0;
    }

    if (handle_user_stack_fault(page) == 0 &&
        get_physical_address(pgdir, page)) {
        note_kernel_resolved_user_fault(false);
        return 0;
    }

    return -1;
}

static int fault_in_user_range(pgdir_t pgdir, const void *ptr, size_t size,
                               bool is_write)
{
    vaddr_t start = (vaddr_t)(uintptr_t)ptr;
    vaddr_t end = start + size - 1;
    vaddr_t page = start & PAGE_MASK;
    vaddr_t last_page = end & PAGE_MASK;

    if (!pgdir || !is_valid_user_range(ptr, size))
        return -1;

    while (page <= last_page) {
        if (fault_in_user_page(pgdir, page, is_write) < 0)
            return -1;

        if (page > 0xFFFFFFFFu - PAGE_SIZE)
            break;
        page += PAGE_SIZE;
    }

    return 0;
}

static int copy_to_user_pages(pgdir_t pgdir, vaddr_t user_addr,
                              const uint8_t *src, size_t n)
{
    size_t copied = 0;

    while (copied < n) {
        vaddr_t current = user_addr + copied;
        paddr_t phys = get_physical_address(pgdir, current);
        size_t chunk = PAGE_SIZE - (current & (PAGE_SIZE - 1));

        if (!phys) {
            if (fault_in_user_page(pgdir, current & PAGE_MASK, true) < 0)
                return -1;
            phys = get_physical_address(pgdir, current);
            if (!phys)
                return -1;
        }

        if (chunk > n - copied)
            chunk = n - copied;

        /*
         * User pages live in RAM that is directly mapped in the kernel.  Copy
         * through the resolved physical address instead of touching the user
         * virtual address directly; otherwise a partially unmapped user range
         * can abort the kernel inside memcpy().
         */
        memcpy((void *)phys_to_virt(phys), src + copied, chunk);
        copied += chunk;
    }

    return 0;
}

static int copy_from_user_pages(pgdir_t pgdir, uint8_t *dst,
                                vaddr_t user_addr, size_t n)
{
    size_t copied = 0;

    while (copied < n) {
        vaddr_t current = user_addr + copied;
        paddr_t phys = get_physical_address(pgdir, current);
        size_t chunk = PAGE_SIZE - (current & (PAGE_SIZE - 1));

        if (!phys) {
            if (fault_in_user_page(pgdir, current & PAGE_MASK, false) < 0)
                return -1;
            phys = get_physical_address(pgdir, current);
            if (!phys)
                return -1;
        }

        if (chunk > n - copied)
            chunk = n - copied;

        memcpy(dst + copied, (const void *)phys_to_virt(phys), chunk);
        copied += chunk;
    }

    return 0;
}

vaddr_t map_user_to_kernel(pgdir_t pgdir, vaddr_t vaddr){

    //uint32_t user_addr = vaddr;
    //uint32_t user_page = user_addr & ~0xFFF;
    //uint32_t offset = user_addr & 0xFFF;

    //KDEBUG("map_user_to_kernel --------------------------\n");

    paddr_t phys_addr = get_phys_addr_from_pgdir(pgdir, vaddr);

    //KDEBUG("after get_phys_addr_from_pgdir ---- Physical Address 0x%08x ---- PGDIR = 0x%08X-------\n", phys_addr, pgdir);

    vaddr_t user_page = map_temp_page(phys_addr);

    //KDEBUG("after map_temp_user_page ---- 0x%08x ----------------\n", user_page);


    return user_page;
}


/* Helper functions */
int copy_to_user(void* to, const void* from, size_t n)
{
    task_t* task = get_current_task();
    pgdir_t pgdir = (task && task->type == TASK_TYPE_PROCESS &&
                     task->process && task->process->vm)
                  ? task->process->vm->pgdir
                  : NULL;
    vaddr_t to_addr = (vaddr_t)(uintptr_t)to;
    vaddr_t from_addr = (vaddr_t)(uintptr_t)from;

    /* Verifications de securite de base */
    if (!to || !from || n == 0 || !pgdir) {
        return -1;  /* Pointeurs invalides */
    }
    
    /* Verifier que 'to' est dans l'espace utilisateur */
    if (!is_valid_user_range(to, n)) {
        KERROR("[COPY] ERROR: copy_to_user destination 0x%08X+%u not in user space\n", 
                to_addr, n);
        return -1;
    }
    
    /* Verifier que 'from' est dans l'espace kernel */
    if (!IS_KERNEL_ADDR(from_addr)) {
        KERROR("[COPY] ERROR: copy_to_user source 0x%08X not in kernel space\n", 
                from_addr);
        return -1;
    }
    
    /* Verifier le debordement */
    if (to_addr + n < to_addr) {
        return -1;  /* Overflow */
    }

    if (fault_in_user_range(pgdir, to, n, true) < 0 ||
        !is_mapped_user_range(pgdir, to, n)) {
        KERROR("[COPY] ERROR: copy_to_user destination 0x%08X+%u is not mapped\n",
                to_addr, n);
        return -1;
    }

    if (copy_to_user_pages(pgdir, to_addr, (const uint8_t *)from, n) < 0) {
        KERROR("[COPY] ERROR: copy_to_user destination 0x%08X+%u mapping changed during copy\n",
                to_addr, n);
        return -1;
    }

    //hexdump((void *)to, 32);
    return 0;
}


int copy_from_user(void* to, const void* from, size_t n)
{
    task_t* task = get_current_task();
    pgdir_t pgdir = (task && task->type == TASK_TYPE_PROCESS &&
                     task->process && task->process->vm)
                  ? task->process->vm->pgdir
                  : NULL;
    vaddr_t to_addr = (vaddr_t)(uintptr_t)to;
    vaddr_t from_addr = (vaddr_t)(uintptr_t)from;

    //KDEBUG("copy_from_user: Starting to copy...\n");


    /* Verifications de securite de base */
    if (!to || !from || n == 0 || !pgdir) {
        return -1;  /* Pointeurs invalides */
    }
   
    /* Verifier que 'from' est dans l'espace utilisateur */
    if (!is_valid_user_range(from, n)) {
        KERROR("[COPY] ERROR: copy_from_user source 0x%08X+%u not in user space\n", 
                from_addr, n);
        return -1;
    }
    
    /* Verifier que 'to' est dans l'espace kernel */
    if (!IS_KERNEL_ADDR(to_addr)) {
        KERROR("[COPY] ERROR: copy_from_user destination 0x%08X not in kernel space\n", 
                to_addr);
        return -1;
    }
    
    /* Verifier le debordement */
    if (from_addr + n < from_addr) {
        return -1;  /* Overflow */
    }

    if (fault_in_user_range(pgdir, from, n, false) < 0 ||
        !is_mapped_user_range(pgdir, from, n)) {
        KERROR("[COPY] ERROR: copy_from_user source 0x%08X+%u is not mapped\n",
                from_addr, n);
        return -1;
    }

    //KDEBUG("copy_from_user: All controls OK mapping address to kernel...\n");
    
    //KDEBUG("current pgdir = 0x%08X\n", pgdir);
    //KDEBUG("temp_page = 0x%08X\n", temp_page);
    //KDEBUG("offset = 0x%08X\n", offset);

    //hexdump( (void *)((uint32_t)temp_page + offset) , 32);

    //char *test_str = (char *)((uint32_t)temp_page + offset);

    //KDEBUG("test_str = %s of len = %d\n", test_str, strlen(test_str));
    
    if (copy_from_user_pages(pgdir, (uint8_t *)to, from_addr, n) < 0) {
        KERROR("[COPY] ERROR: copy_from_user source 0x%08X+%u mapping changed during copy\n",
                from_addr, n);
        return -1;
    }
    //memcpy(to, (void *)test_str, strlen(test_str));


    //KDEBUG("TO = %s of len = %d\n", to, strlen(to));


    //unmap_temp_page(temp_page);

    return 0;
}

/* === FONCTIONS COMPAGNONS UTILES === */

/* Version pour strings avec limite */
int strncpy_from_user(char* to, const char* from, size_t max_len)
{
    if (!to || !from || max_len == 0) {
        return -1;
    }
    
    /* Verifier que 'from' est dans l'espace utilisateur */
    if (!is_valid_user_ptr(from)) {
        return -1;
    }
    
    /* Verifier que 'to' est dans l'espace kernel */
    if (!IS_KERNEL_ADDR((vaddr_t)(uintptr_t)to)) {
        return -1;
    }
    
    /* Copie caractere par caractere avec verification */
    size_t i;
    for (i = 0; i < max_len - 1; i++) {
        /* Verifier que chaque caractere est accessible */
        if (!is_valid_user_ptr(from + i)) {
            break;
        }
        
        to[i] = from[i];
        if (from[i] == '\0') {
            return i;  /* Succes, retourne la longueur */
        }
    }
    
    to[i] = '\0';  /* Terminer la chaine */
    return (from[i] == '\0') ? (int)i : -1;  /* -1 si tronque */
}

/* Version pour copier vers user avec limite */
int copy_to_user_safe(void* to, const void* from, size_t n, size_t max_size)
{
    if (n > max_size) {
        return -1;  /* Taille trop grande */
    }
    
    return copy_to_user(to, from, n);
}


char* copy_string_from_user(const char* user_str)
{
    int len;
    char* kernel_str;

    
    if (!user_str || !is_valid_user_ptr(user_str)) return NULL;
    
    /* Calculate length with limit */
    //len = strnlen_user(user_str, 4096);
    len = strlen(user_str);
    if (len < 0) return NULL;
    
    kernel_str = kmalloc(len + 1);
    if (!kernel_str) return NULL;
    memset(kernel_str, 0, len + 1);

    //KDEBUG("copy_string_from_user: About to copy from user...\n");
    
    if (copy_from_user(kernel_str, user_str, len ) < 0) {
        kfree(kernel_str);
        return NULL;
    }

    kernel_str[len]='\0';

    //KDEBUG("kernel_str = *%s*\n", kernel_str);
    
    return kernel_str;
}

char** copy_argv_from_user(char* const user_argv[], uint32_t argc)
{
    //int argc = 0;
    char** kernel_argv;
    int i;
    int j;
    
    if (!user_argv) return NULL;
    
    /* Count arguments */
    //while (argc < 32 && user_argv[argc]) {
    //    argc++;
    //}

    kernel_argv = kmalloc((argc + 1) * sizeof(char*));
    if (!kernel_argv) return NULL;
    
    for (i = 0; i < (int)argc; i++) {
        if(user_argv[i])
        {
            kernel_argv[i] = copy_string_from_user(user_argv[i]);
            if (!kernel_argv[i]) {

                break;
                 // Cleanup on error 
                for (j = 0; j < i; j++) {
                    kfree(kernel_argv[j]);
                }
                kfree(kernel_argv);
                return NULL; 
            }
        }
        else
        {
            kfree(kernel_argv[i]);
            kernel_argv[i] = NULL;
        }
    }
    kernel_argv[argc] = NULL;
    
    return kernel_argv;
}

void cleanup_exec_args(char* filename, char** argv, char** envp)
{
    int i;
    
    if (filename) kfree(filename);
    
    if (argv) {
        for (i = 0; argv[i]; i++) {
            if (argv[i]) kfree(argv[i]);
        }
        kfree(argv);
    }
    
    if (envp) {
        for (i = 0; envp[i]; i++) {
            if (envp[i]) kfree(envp[i]);
        }
        kfree(envp);
    }
}

int count_strings(char** strings)
{
    int count = 0;
    if (strings) {
        while (strings[count]) {
            count++;
        }
    }
    return count;
}

char** setup_stack_strings(char** strings, char** stack_ptr, int count,
                           vaddr_t temp_stack, vaddr_t user_stack_page)
{
    if (!strings) return NULL;
    
    if (count == 0) return NULL;
    
    // Allouer tableau pour les pointeurs
    char** result = kmalloc(count * sizeof(char*));
    if (!result) return NULL;
    
    // Copier chaque string sur la pile
    for (int i = 0; i < count; i++) {
        if (!strings[i]) {
            result[i] = NULL;
            continue;
        }
        
        int len = strlen(strings[i]) + 1;
        *stack_ptr -= len;  // Reculer stack_ptr
        
        // Copier la string
        strcpy(*stack_ptr, strings[i]);
        result[i] = (char*)(user_stack_page + ((uintptr_t)*stack_ptr - (uintptr_t)temp_stack));
    }
    
    return result;
}

void copy_string_array(char** src, char** dest, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        dest[i] = src[i];
    }
    dest[count] = NULL;
}

/*
static char* copy_string_from_user(const char* user_str)
{
    int len;
    char* kernel_str;
    
    if (!user_str) return NULL;
    
    len = strnlen_user(user_str, 4096);
    if (len < 0) return NULL;
    
    kernel_str = kmalloc(len + 1);
    if (!kernel_str) return NULL;
    
    if (copy_from_user(kernel_str, user_str, len) < 0) {
        kfree(kernel_str);
        return NULL;
    }
    
    kernel_str[len] = '\0';
    return kernel_str;
}
    */



/*
static char* copy_string_from_user_local(const char* user_str)
{
    int len;
    char* kernel_str;
    
    if (!user_str) return NULL;
    
    len = strnlen_user_local(user_str, 4096);
    if (len < 0) return NULL;
    
    kernel_str = kmalloc(len + 1);
    if (!kernel_str) return NULL;
    
    if (copy_from_user(kernel_str, user_str, len) < 0) {
        kfree(kernel_str);
        return NULL;
    }
    
    kernel_str[len] = '\0';
    return kernel_str;
}
    */


int setup_user_stack(vm_space_t* vm, char** argv, char** envp)
{
    /* Create VMA for stack */
    uint32_t stack_size = USER_STACK_SIZE;
    vaddr_t stack_start = USER_STACK_TOP - stack_size;
    vma_t* stack_vma;
    void* stack_page;
    vaddr_t stack_top_page;
    vaddr_t temp_stack;
    char* stack_ptr;
    int argc;
    int envc;
    char** stack_argv;
    char** stack_envp;
    char** envp_array;
    char** argv_array;
    vaddr_t final_sp;
    
    stack_vma = create_vma(vm, stack_start, stack_size, VMA_READ | VMA_WRITE);
    if (!stack_vma) return -1;

    //KDEBUG("After create VMA USER STACK - Start = 0x%08X, Top = 0x%08X, Size = %u MB\n", stack_start, stack_start + stack_size, stack_size/1024/1024);
    
    /* Allocate page for top of stack */
    stack_page = allocate_page();
    if (!stack_page) return -1;
    
    //KDEBUG("After allocate_page\n");

    //stack_top_page = USER_STACK_TOP - PAGE_SIZE;
    stack_top_page = (USER_STACK_TOP - PAGE_SIZE) & ~0xFFF; 
    if (map_user_page(vm->pgdir, stack_top_page, (paddr_t)stack_page,
                      VMA_READ | VMA_WRITE, vm->asid) < 0) {
        free_page(stack_page);
        return -1;
    }

    //KDEBUG("After map_user_page\n");
    
    /* Map temporarily for setup */
    temp_stack = map_temp_page((paddr_t)stack_page);
    stack_ptr = (char*)(temp_stack + PAGE_SIZE - 4);


    //KDEBUG("After map_temp_page\n");
    
    /* Count arguments */
    argc = count_strings(argv);
    envc = count_strings(envp);

    //KDEBUG("After count_strings\n");    
    
    /* Setup stack layout */
    stack_argv = setup_stack_strings(argv, &stack_ptr, argc, temp_stack, stack_top_page);
    stack_envp = setup_stack_strings(envp, &stack_ptr, envc, temp_stack, stack_top_page);

    //KDEBUG("After setup_stack_strings\n");     
    
    /* Align stack */
    stack_ptr = (char*)((uintptr_t)stack_ptr & ~((uintptr_t)7));
    
    /* Build arrays */
    stack_ptr -= (envc + 1) * sizeof(char*);
    //KDEBUG("New Stack PTR = 0x%08X\n", stack_ptr);  
    envp_array = (char**)stack_ptr;
    //KDEBUG("New envp_array PTR = 0x%08X, stack_envp=0x%08X, envc=%d\n", envp_array, stack_envp, envc); 
    copy_string_array(stack_envp, envp_array, envc);
    //KDEBUG("After copy_string_array envp\n");  
    
    stack_ptr -= (argc + 1) * sizeof(char*);
    //KDEBUG("New Stack PTR = 0x%08X\n", stack_ptr);     
    argv_array = (char**)stack_ptr;
    //KDEBUG("New argv_array PTR = 0x%08X, stack_argv=0x%08X, argc=%d\n", argv_array, stack_argv, argc); 
    copy_string_array(stack_argv, argv_array, argc);
    //KDEBUG("After copy_string_array argv\n");  

    
    /* argc */
    stack_ptr -= sizeof(int);
    *(int*)stack_ptr = argc;
    
    /* Calculate final SP for user space */
    //final_sp = USER_STACK_TOP - (PAGE_SIZE - ((uintptr_t)stack_ptr - temp_stack));
    uint32_t offset_in_page = (uint32_t)((uintptr_t)stack_ptr - (uintptr_t)temp_stack);
    final_sp = stack_top_page + offset_in_page;
    vm->stack_start = final_sp;

    //KDEBUG("  Offset in page: 0x%08X\n", offset_in_page);
    //KDEBUG("  Final SP calculation: 0x%08X + 0x%08X = 0x%08X\n", 
    //    stack_top_page, offset_in_page, final_sp);

    /* Vérifier que final_sp est dans la page mappée */
    if (final_sp >= stack_top_page && final_sp < stack_top_page + PAGE_SIZE) {
        //KDEBUG("  Final SP is in mapped page \n");
    } else {
        KERROR("  Final SP is OUTSIDE mapped page!\n");
        KERROR("    final_sp: 0x%08X\n", final_sp);
        KERROR("    page: 0x%08X - 0x%08X\n", stack_top_page, stack_top_page + PAGE_SIZE - 1);
    }

    //KDEBUG("=== STACK SETUP VERIFICATION ===\n");
    //KDEBUG("  USER_STACK_TOP: 0x%08X\n", USER_STACK_TOP);
    //KDEBUG("  stack_top_page: 0x%08X\n", stack_top_page);
    //KDEBUG("  Page range: 0x%08X - 0x%08X\n", stack_top_page, stack_top_page + PAGE_SIZE - 1);
    //KDEBUG("  Stack Pointer: 0x%08X \n", vm->stack_start);

    /* Vérifier les adresses critiques */
/*     uint32_t test_addresses[] = {
        0x3EFFFFF4,  // Adresse du fault 
        0x3EFFFFFC,  // SP utilisateur 
        USER_STACK_TOP - 4,
        final_sp
    };

    for (int i = 0; i < 4; i++) {
        uint32_t addr = test_addresses[i];
        bool in_page = (addr >= stack_top_page && addr < stack_top_page + PAGE_SIZE);
        KDEBUG("  Address 0x%08X: %s\n", addr, in_page ? "✓ IN PAGE" : "✗ OUT OF PAGE");
    }

    KDEBUG("  Final SP: 0x%08X\n", final_sp); */
    
    unmap_temp_page((void*)temp_stack);
    
    kfree(stack_argv);
    kfree(stack_envp);
    
    return 0;
}

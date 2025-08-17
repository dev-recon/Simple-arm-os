#include <kernel/kernel.h>
#include <kernel/types.h>
#include <asm/mmu.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>



/* === MACROS UTILITAIRES === */


bool is_valid_user_ptr(const void* ptr)
{
    return IS_USER_ADDR((uint32_t)ptr);
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

void unmap_user_page(uint32_t* pgdir, uint32_t vaddr)
{
    uint32_t pd_index = get_L1_index(vaddr);
    
    /* Simplified implementation - just clear the page directory entry */
    if (pd_index < 4096) {
        pgdir[pd_index] = 0;
    }
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
    uint32_t start = (uint32_t)ptr;
    uint32_t end = start + size;
    
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
    if (start < USER_SPACE_START || end > USER_SPACE_END) {
        return false;
    }
    
    return true;
}



/* Helper functions */
int copy_to_user(void* to, const void* from, size_t n)
{
    /* Verifications de securite de base */
    if (!to || !from || n == 0) {
        return -1;  /* Pointeurs invalides */
    }
    
    /* Verifier que 'to' est dans l'espace utilisateur */
    if (!is_valid_user_range(to, n)) {
        KERROR("[COPY] ERROR: copy_to_user destination 0x%08X+%u not in user space\n", 
                (uint32_t)to, n);
        return -1;
    }
    
    /* Verifier que 'from' est dans l'espace kernel */
    if (!IS_KERNEL_ADDR((uint32_t)from)) {
        KERROR("[COPY] ERROR: copy_to_user source 0x%08X not in kernel space\n", 
                (uint32_t)from);
        return -1;
    }
    
    /* Verifier le debordement */
    if ((uint32_t)to + n < (uint32_t)to) {
        return -1;  /* Overflow */
    }
    
    /* Copie securisee */
    memcpy(to, from, n);
    return 0;
}

int copy_from_user(void* to, const void* from, size_t n)
{
    /* Verifications de securite de base */
    if (!to || !from || n == 0) {
        return -1;  /* Pointeurs invalides */
    }
    
    /* Verifier que 'from' est dans l'espace utilisateur */
    if (!is_valid_user_range(from, n)) {
        KERROR("[COPY] ERROR: copy_from_user source 0x%08X+%u not in user space\n", 
                (uint32_t)from, n);
        return -1;
    }
    
    /* Verifier que 'to' est dans l'espace kernel */
    if (!IS_KERNEL_ADDR((uint32_t)to)) {
        KERROR("[COPY] ERROR: copy_from_user destination 0x%08X not in kernel space\n", 
                (uint32_t)to);
        return -1;
    }
    
    /* Verifier le debordement */
    if ((uint32_t)from + n < (uint32_t)from) {
        return -1;  /* Overflow */
    }
    
    /* Copie securisee */
    memcpy(to, from, n);
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
    if (!IS_KERNEL_ADDR((uint32_t)to)) {
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
    
    //KDEBUG("JE SUIS ICI ===============================\n");
    /* Calculate length with limit */
    len = strnlen_user(user_str, 4096);
    if (len < 0) return NULL;
    
    kernel_str = kmalloc(len + 1);
    if (!kernel_str) return NULL;
    
    if (copy_from_user(kernel_str, user_str, len + 1) < 0) {
        kfree(kernel_str);
        return NULL;
    }
    
    return kernel_str;
}

char** copy_argv_from_user(char* const user_argv[])
{
    int argc = 0;
    char** kernel_argv;
    int i;
    int j;
    
    if (!user_argv) return NULL;
    
    /* Count arguments */
    while (argc < 32 && user_argv[argc]) {
        argc++;
    }
    
    kernel_argv = kmalloc((argc + 1) * sizeof(char*));
    if (!kernel_argv) return NULL;
    
    for (i = 0; i < argc; i++) {
        kernel_argv[i] = copy_string_from_user(user_argv[i]);
        if (!kernel_argv[i]) {
            /* Cleanup on error */
            for (j = 0; j < i; j++) {
                kfree(kernel_argv[j]);
            }
            kfree(kernel_argv);
            return NULL;
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
            kfree(argv[i]);
        }
        kfree(argv);
    }
    
    if (envp) {
        for (i = 0; envp[i]; i++) {
            kfree(envp[i]);
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

char** setup_stack_strings(char** strings, char** stack_ptr)
{
    /* Stub implementation */
    (void)strings;
    (void)stack_ptr;
    return NULL;
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
    uint32_t stack_start = USER_STACK_TOP - stack_size;
    vma_t* stack_vma;
    void* stack_page;
    uint32_t stack_top_page;
    uint32_t temp_stack;
    char* stack_ptr;
    int argc;
    int envc;
    char** stack_argv;
    char** stack_envp;
    char** envp_array;
    char** argv_array;
    uint32_t final_sp;
    
    stack_vma = create_vma(vm, stack_start, stack_size, VMA_READ | VMA_WRITE);
    if (!stack_vma) return -1;
    
    /* Allocate page for top of stack */
    stack_page = allocate_physical_page();
    if (!stack_page) return -1;
    
    //stack_top_page = USER_STACK_TOP - PAGE_SIZE;
    stack_top_page = USER_STACK_TOP & ~0xFFF; 
    map_user_page(vm->pgdir, stack_top_page, (uint32_t)stack_page, VMA_READ | VMA_WRITE);
    
    /* Map temporarily for setup */
    temp_stack = map_temp_page((uint32_t)stack_page);
    stack_ptr = (char*)(temp_stack + PAGE_SIZE - 4);
    
    /* Count arguments */
    argc = count_strings(argv);
    envc = count_strings(envp);
    
    /* Setup stack layout */
    stack_argv = setup_stack_strings(argv, &stack_ptr);
    stack_envp = setup_stack_strings(envp, &stack_ptr);
    
    /* Align stack */
    stack_ptr = (char*)((uint32_t)stack_ptr & ~7);
    
    /* Build arrays */
    stack_ptr -= (envc + 1) * sizeof(char*);
    envp_array = (char**)stack_ptr;
    copy_string_array(stack_envp, envp_array, envc);
    
    stack_ptr -= (argc + 1) * sizeof(char*);
    argv_array = (char**)stack_ptr;
    copy_string_array(stack_argv, argv_array, argc);
    
    /* argc */
    stack_ptr -= sizeof(int);
    *(int*)stack_ptr = argc;
    
    /* Calculate final SP for user space */
    //final_sp = USER_STACK_TOP - (PAGE_SIZE - ((uint32_t)stack_ptr - temp_stack));
    uint32_t offset_in_page = (uint32_t)stack_ptr - temp_stack;
    final_sp = stack_top_page + offset_in_page;
    vm->stack_start = final_sp;

    //KDEBUG("  Offset in page: 0x%08X\n", offset_in_page);
    //KDEBUG("  Final SP calculation: 0x%08X + 0x%08X = 0x%08X\n", 
    //    stack_top_page, offset_in_page, final_sp);

    /* Vérifier que final_sp est dans la page mappée */
    if (final_sp >= stack_top_page && final_sp < stack_top_page + PAGE_SIZE) {
        //KDEBUG("  Final SP is in mapped page ✓\n");
    } else {
        KERROR("  Final SP is OUTSIDE mapped page!\n");
        KERROR("    final_sp: 0x%08X\n", final_sp);
        KERROR("    page: 0x%08X - 0x%08X\n", stack_top_page, stack_top_page + PAGE_SIZE - 1);
    }

    //KDEBUG("=== STACK SETUP VERIFICATION ===\n");
    //KDEBUG("  USER_STACK_TOP: 0x%08X\n", USER_STACK_TOP);
    //KDEBUG("  stack_top_page: 0x%08X\n", stack_top_page);
    //KDEBUG("  Page range: 0x%08X - 0x%08X\n", stack_top_page, stack_top_page + PAGE_SIZE - 1);

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

/* kernel/main.c */
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/interrupt.h>
#include <kernel/timer.h>
#include <kernel/keyboard.h>
#include <kernel/display.h>
#include <kernel/vfs.h>
#include <kernel/ata.h>

/* Inclusion des fonctions inline ARM apres les prototypes */
#include <asm/arm.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/debug_print.h>
#include <kernel/stdarg.h>
#include <kernel/ide.h>
#include <kernel/ramfs.h>
#include <kernel/userfs_loader.h>

#include <kernel/task.h>
#include <kernel/kernel_tasks.h>

//extern void test_utoa_direct();
//extern void simple_utoa(unsigned int val, char *str, int base);


// Canary statique
uintptr_t __stack_chk_guard = 0xDEADBEEF;

// Appelée si débordement détecté
void __attribute__((noreturn)) __stack_chk_fail(void) {
    // Panic ou halt, au choix
    extern void panic(const char*);
    panic("Stack smashing detected");
    while (1) {}
}


static void halt_system(void) {
    __asm__ volatile(
        "1: b 1b"  // Boucle infinie en assembleur
        :
        :
        : "memory"
    );
}

void init_early_uart(void)
{
    volatile uint32_t* uart = (volatile uint32_t*)UART0_BASE;
    
    /* Disable UART */
    uart[0x30/4] = 0;
    
    /* Configure baud rate (38400) */
    uart[0x24/4] = 1;   /* UARTIBRD */
    uart[0x28/4] = 40;  /* UARTFBRD */
    
    /* Configure format: 8N1 */
    uart[0x2C/4] = (3 << 5);
    
    /* Enable UART, TX, RX */
    uart[0x30/4] = (1 << 0) | (1 << 8) | (1 << 9);
}

void panic(const char* message)
{
    disable_interrupts();
    uart_puts("KERNEL PANIC: ");
    uart_puts(message);
    uart_puts("\n");
    
    while (1) {
        wait_for_interrupt();
    }
}


static void print_system_info(void);
static void test_armv7a_features(void);
static void test_memory_barriers(void);
static void test_coprocessors(void);
static uint32_t read_cpu_id(void);
static uint32_t read_mpidr(void);
static uint32_t read_sctlr(void);
static void demonstrate_cache_ops(void);

/* Forward declarations */
void early_init(void); 
void kernel_main(void);

static inline void disable_branch_predictor(void) {
    uint32_t sctlr;

    // Lire SCTLR
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));

    // Clear bit Z (bit 11)
    sctlr &= ~(1 << 11);

    // Écrire SCTLR modifié
    asm volatile("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));

    // Flush BPIALL (invalidate branch predictor state)
    asm volatile("mcr p15, 0, %0, c7, c5, 6" :: "r"(0));
    asm volatile("isb");
}

void early_init(void)
{
    /* Phase 1: Hardware de base uniquement */
    uart_init();
    
    /* Phase 2: Detection memoire pour MMU */
    kernel_memory_size = detect_memory();
    
    if (kernel_memory_size > 0) {
        kprintf("Memory detected (bytes): %u\n", kernel_memory_size);
        kprintf("Memory detected (MB): %u\n", kernel_memory_size / (1024*1024));

        /* Phase 3: Setup MMU - AVANT tout allocateur */
        kprintf("Setting up MMU...\n");
        if (setup_mmu()) {
            kprintf("MMU setup OK\n");
            debug_mmu_state();
        } else {
            panic("MMU setup FAILED - cannot continue");
        }
    } else {
        kprintf("Memory detected (bytes): %u\n", kernel_memory_size);
        kprintf("Memory detected (MB): %u / %llu\n", kernel_memory_size / (1024*1024), 2ULL*1024*1024*1024);

        panic("Memory detection returned suspicious value");
    } 
    
    kprintf("Early init complete\n");
}


/* Ajoutez cette fonction dans votre kernel */
void test_heap_health(const char* phase_name)
{
    kprintf("=== HEAP TEST: %s ===\n", phase_name);
    
    void* test = kmalloc(64);
    if (test) {
        kprintf("OK %s: Heap OK\n", phase_name);
        kfree(test);
    } else {
        kprintf("KO %s: HEAP CORRUPTED!\n", phase_name);
        
        /* Debug detaille */
        extern void* free_list;  /* Ajustez selon votre implementation */
        kprintf("  free_list: %p\n", free_list);
        
        if (free_list) {
            /* Essayez de lire la premiere structure (prudemment) */
            volatile uint32_t* ptr = (volatile uint32_t*)free_list;
            kprintf("  first_block[0]: 0x%08X\n", ptr[0]);
            kprintf("  first_block[1]: 0x%08X\n", ptr[1]);
        }
    }
}

/*
 * Point d'entree principal du kernel ARMv7-A
 */
void kernel_main(void)
{
    extern void test_process_structure_offsets(void);
    extern void launch_first_process(process_t* proc);
    extern void test_process_system_with_ls(void);
    extern void ls_process_main(const char* path);
    extern void test_ramfs_cluster_content(void);
    extern void debug_memory_layout_ramfs(void);

    /* Phase 0: etats du processeur */
    __asm__ volatile ("cpsie aif");

    sctlr_set_smp();

    uint32_t cpsr;
    __asm__ volatile ("mrs %0, cpsr" : "=r"(cpsr));

    kprintf("CPSR = 0x%08X\n", cpsr);
    kprintf(" IRQ: %s\n", (cpsr & (1 << 7)) ? "DISABLED" : "ENABLED");
    kprintf(" FIQ: %s\n", (cpsr & (1 << 6)) ? "DISABLED" : "ENABLED");
    kprintf(" ABT: %s\n", (cpsr & (1 << 8)) ? "DISABLED" : "ENABLED");
    kprintf("ACTLR.SMP = %d\n", sctlr_smp_enabled());
    
    uint32_t vbar;
    __asm__ volatile ("mrc p15, 0, %0, c12, c0, 0" : "=r"(vbar));
    kprintf("[CPU] VBAR = 0x%08X\n", vbar);
    
    extern void vectors(void);
    extern void irq_handler(void);
    kprintf("[DEBUG] Vectors address = %p\n", vectors);
    kprintf("[CHECK] irq_handler = %p\n", irq_handler);

    KDEBUG("=== STARTING KERNEL INITIALIZATION ===\n");

    //disable_branch_predictor();
    
    kprintf("Initialize physical memory allocator ... ");
    init_memory();  // <- Allocateur physique EN PREMIER
    kprintf("OK\n");

    /* Phase 1: Initialisation critique (MMU, memoire de base) */
    kprintf("Phase 1: Core initialization...\n");
    early_init();  // MMU + detection memoire

    /* Phase 2: Allocateurs memoire (DANS L'ORDRE !) */
    kprintf("Phase 2: Memory management...\n");
    


    kprintf("Initialize Stack for SVC Mode ... ");
    setup_svc_stack();
    kprintf("OK\n");

    /* Phase 3: Controleurs materiels de base */
    kprintf("Phase 3: Hardware controllers...\n");
    
    kprintf("Initialize interrupt controller ... ");

    init_gic();

    //init_timer_software();
    init_timer();

    kprintf("=== STARTING MAIN LOOP ===\n");

    /* Banner de demarrage */
    kprintf("\n");
    kprintf("=========================================\n");
    kprintf("    Kernel ARMv7-A Cortex-A15\n");  // <- Corrige !
    kprintf("    Developpe sur Mac M4\n");
    kprintf("    Cible: QEMU machine virt\n");     // <- Corrige !
    kprintf("=========================================\n\n");
    
    /* Informations systeme detaillees */
    print_system_info();
   
    /* Tests des fonctionnalites ARMv7-A */
    test_armv7a_features();

    /* Phase 4: Peripheriques d'entree/sortie */
    kprintf("Phase 4: I/O devices...\n");

    kprintf("Initialize keyboard ... \n");
    init_keyboard();
    kprintf("OK\n");
  
    kprintf("Initialize display ... \n");
    init_display();
    kprintf("OK\n");
      
    //kprintf("Initialize IDE ... ");
    //init_ide();
    //ide_comprehensive_test();
    //kprintf("OK\n");

    /* Phase 6: Activation des interruptions */
    kprintf("Phase 6: Interrupt activation...\n");
    kprintf("Enable timer for scheduling ... ");
    timer_enable_scheduling();
    kprintf("OK\n");
 
    kprintf("Enable interrupts ... ");
    enable_interrupts();
    kprintf("OK\n");

    /* Phase 7: Systemes de fichiers (OPTIONNEL) */
    kprintf("Phase 7: File systems...\n");
    
    // Decommente si necessaire

#ifdef USE_RAMFS
    kprintf("Initialize RAMFS ... ");
    if (/*init_ramfs()*/0) { 
    kprintf("----------------> OK\n");
} else {
    kprintf("----------------> FAILED\n");
}

#endif

    kprintf("Initialize ATA ... ");
    if (!init_ata()) {
        kprintf("Warning: ATA initialization failed\n");
    } else {
        kprintf("OK\n");
    }

    kprintf("Initialize VFS ... ");

    if (!init_vfs()) {
        kprintf("Warning: VFS initialization failed\n");
    } else {
        kprintf("OK\n");
    }    

    /* Finalisation */
    kprintf("ARM32 Kernel initialization complete\n");
    
    kprintf("\nTARGET Kernel ARMv7-A operationnel!\n");
    kprintf("- Cross-compiled from Mac M4\n");
    kprintf("- Caches L1 et prediction actives\n\n");
    
    kprintf("Kernel up and running ...\n");
    kprintf("Use Ctrl+A and X to exit QEMU\n");


    //trigger_timer_interrupt();
    /* Phase 5: Gestion des processus (APReS allocateurs) */
    kprintf("Phase 5: Process management...\n");
    
    /* Main scheduler loop */
    init_main() ;

}


/*
 * Affichage des informations systeme ARMv7-A
 */
void print_system_info(void)
{
    kprintf("=== Informations CPU ARMv7-A ===\n");
    kprintf("CPU ID (MIDR): 0x%08X\n", read_cpu_id());
    kprintf("MPIDR: 0x%08X\n", read_mpidr());
    kprintf("SCTLR: 0x%08X\n", read_sctlr());
    kprintf("Kernel @ %p\n", kernel_main);
    
    extern uint32_t __bss_start, __bss_end;
    kprintf("BSS: %p - %p\n", &__bss_start, &__bss_end);
}

/*
 * Tests des fonctionnalites ARMv7-A
 */
static void test_armv7a_features(void)
{
    kprintf("=== Tests ARMv7-A ===\n");
    
    /* Test des barrieres memoire */
    kprintf("- Barrieres memoire ARMv7-A... ");
    test_memory_barriers();
    kprintf("OK\n");
    
    /* Test des coprocesseurs */
    kprintf("- Acces coprocesseurs CP15... ");
    test_coprocessors();
    kprintf("OK\n");
    
    /* Test des operations cache */
    kprintf("- Operations cache L1... ");
    demonstrate_cache_ops();
    kprintf("OK\n");
    
    /* Test NEON (si disponible) */
    kprintf("- Test NEON/VFP... ");
    uint32_t cpacr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 2" : "=r"(cpacr));
    if (cpacr & (3 << 20)) {
        kprintf("OK (VFP disponible)\n");
    } else {
        kprintf("WARNING  (VFP desactive)\n");
    }
    
    /* Test des instructions conditionnelles ARMv7-A */
    kprintf("- Instructions conditionnelles... ");
    uint32_t test_val = 42;
    uint32_t result;
    
    __asm__ volatile(
        "cmp %1, #42\n"
        "moveq %0, #1\n"      /* Si egal, result = 1 */
        "movne %0, #0"        /* Si different, result = 0 */
        : "=r"(result)
        : "r"(test_val)
        : "cc"
    );
    
    if (result == 1) {
        kprintf("OK\n");
    } else {
        kprintf("KO\n");
    }
    
    kprintf("\n");
    
}

/*
 * Test des barrieres memoire ARMv7-A
 */
static void test_memory_barriers(void)
{
    /* ARMv7-A supporte toutes les barrieres modernes */
    __asm__ volatile("dsb");    /* Data Synchronization Barrier */
    __asm__ volatile("dmb");    /* Data Memory Barrier */
    __asm__ volatile("isb");    /* Instruction Synchronization Barrier */
    
    /* Variants specifiques ARMv7-A */
    __asm__ volatile("dsb sy"); /* System-wide DSB */
    __asm__ volatile("dmb sy"); /* System-wide DMB */
}

/*
 * Test des coprocesseurs ARMv7-A
 */
static void test_coprocessors(void)
{
    uint32_t cache_type, tlb_type;
    
    /* Lire les informations de cache (CTR) */
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 1" : "=r"(cache_type));
    
    /* Lire les informations TLB (TLBTR) */
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 3" : "=r"(tlb_type));
    
    /* Utiliser les valeurs pour eviter l'optimisation */
    (void)cache_type;
    (void)tlb_type;
}

/*
 * Demonstration des operations cache
 */
static void demonstrate_cache_ops(void)
{
    /* Nettoyer et invalider tous les caches */
    __asm__ volatile("mcr p15, 0, r0, c7, c14, 0" ::: "memory");
    
    /* Invalider les TLB */
    __asm__ volatile("mcr p15, 0, r0, c8, c7, 0" ::: "memory");
    
    /* Barrieres apres operations cache */
    __asm__ volatile("dsb");
    __asm__ volatile("isb");
}

/*
 * Fonctions de lecture des registres systeme
 */
static uint32_t read_cpu_id(void)
{
    uint32_t id;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(id));
    return id;
}

static uint32_t read_mpidr(void)
{
    uint32_t mpidr;
    __asm__ volatile("mrc p15, 0, %0, c0, c0, 5" : "=r"(mpidr));
    return mpidr;
}

static uint32_t read_sctlr(void)
{
    uint32_t sctlr;
    __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    return sctlr;
}


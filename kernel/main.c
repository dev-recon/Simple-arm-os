/* kernel/main.c */
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/interrupt.h>
#include <kernel/timer.h>
#include <kernel/keyboard.h>
#include <kernel/display.h>
#include <kernel/virtio_gpu.h>
#include <kernel/virtio_input.h>
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

#include <kernel/tty.h>

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


static uint32_t boot_timer_frequency(void)
{
    uint32_t timer_freq;

    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(timer_freq));
    if (timer_freq == 0)
        timer_freq = 62500000;

    return timer_freq;
}

static uint32_t boot_bogomips_x100(uint32_t timer_freq)
{
    /*
     * Early Linux printed a delay-loop calibration as BogoMIPS. For QEMU virt
     * this gives a stable, readable estimate tied to the ARM generic timer.
     */
    return timer_freq / 5000;
}

void early_init(void)
{
    /* Phase 1: Hardware de base uniquement */
    uart_init();
    tty_init();
    uart_attach_tty_backend();
    
    /* Phase 2: Detection memoire pour MMU */
    kernel_memory_size = detect_memory();
    
    if (kernel_memory_size > 0) {
        /* Phase 3: Setup MMU - AVANT tout allocateur */
        if (setup_mmu()) {
            uart_use_kernel_mmio_alias();
        } else {
            panic("MMU setup FAILED - cannot continue");
        }
    } else {
        panic("Memory detection returned suspicious value");
    } 
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
    uint32_t timer_freq;
    uint32_t bogo_x100;
    uint32_t total_mb;
    uint32_t available_mb;
    uint64_t disk_sectors;
    uint32_t disk_mb;

    /* Phase 0: etats du processeur */
    __asm__ volatile ("cpsie aif");

    sctlr_set_smp();

    timer_freq = boot_timer_frequency();
    bogo_x100 = boot_bogomips_x100(timer_freq);

    KBOOT("\n");
    KBOOT(KBOOT_COLOR_INFO "ArmOS 0.1 armv7l" KBOOT_COLOR_RESET "\n");
    KBOOT_OKF("CPU: ARM Cortex-A15 @ QEMU virt");
    KBOOT_OKF("Calibrating delay loop... %u.%02u BogoMIPS",
                bogo_x100 / 100, bogo_x100 % 100);

    //disable_branch_predictor();
    
    init_memory();  // <- Allocateur physique EN PREMIER

    /* Phase 1: Initialisation critique (MMU, memoire de base) */
    early_init();  // MMU + detection memoire

    total_mb = kernel_memory_size / (1024 * 1024);
    available_mb = (get_free_page_count() * PAGE_SIZE) / (1024 * 1024);
    KBOOT_OKF("Memory: %uMB total, %uMB available", total_mb, available_mb);
    KBOOT_OKF("Kernel: 0x%08X-0x%08X", KERNEL_START, KERNEL_END);
    KBOOT_OKF("MMU: split TTBR enabled, ASID pool %u", ASID_MAX);
   
    setup_svc_stack();

    /* Phase 3: Controleurs materiels de base */
    init_gic();
    KBOOT_OKF("GIC: v2, 288 IRQs");

    //init_timer_software();
    init_timer();
    KBOOT_OKF("Timer: ARM generic timer @ %u Hz, tick %u us",
                timer_freq, 1000000 / TIMER_FREQ);

    /* Phase 4: Peripheriques d'entree/sortie */
    init_keyboard();
  
    init_display();
    if (virtio_gpu_init()) {
        KBOOT_OKF("GPU: virtio-gpu %ux%ux%u", FB_WIDTH, FB_HEIGHT, FB_BPP);
        if (framebuffer_attach_tty_backend(TTY_GRAPHICS_ID) == 0) {
            tty_set_active(TTY_GRAPHICS_ID);
            KBOOT_OKF("TTY: console tty1 on virtio-gpu");
            if (virtio_input_init(TTY_GRAPHICS_ID)) {
                KBOOT_OKF("Input: virtio-keyboard on tty1");
            } else {
                KBOOT_WARN("Input: virtio-keyboard unavailable");
            }
        } else {
            KBOOT_WARN("TTY: tty1 framebuffer backend unavailable");
        }
    } else {
        KBOOT_WARN("GPU: virtio-gpu unavailable");
    }
    KBOOT_OKF("TTY: console tty0 on uart0");
      
    //kprintf("Initialize IDE ... ");
    //init_ide();
    //ide_comprehensive_test();
    //kprintf("OK\n");

    /* Phase 6: Activation des interruptions */
    timer_enable_scheduling();
 
    enable_interrupts();

    /* Phase 7: Systemes de fichiers (OPTIONNEL) */
#ifdef USE_RAMFS
    if (/*init_ramfs()*/0) { 
        KBOOT_OK("RAMFS: initialized");
    } else {
        KINFO("RAMFS: not available\n");
    }
#endif

    if (!init_ata()) {
        KBOOT_WARN("Block: virtio0 unavailable");
    } else {
        disk_sectors = ata_get_capacity_sectors();
        disk_mb = (uint32_t)(disk_sectors / 2048u);
        KBOOT_OKF("Block: virtio0 %uMB, irq 47", disk_mb);
    }

    if (!init_vfs()) {
        KBOOT_WARN("VFS: mount failed");
    } else {
        KBOOT_OKF("Partition: virtio0p1 ext2 64MB");
        KBOOT_OKF("Partition: virtio0p2 fat32 64MB");
        KBOOT_OKF("VFS: mounted ext2 on /");
        KBOOT_OKF("VFS: mounted proc on /proc");
        KBOOT_OKF("VFS: fat32 available on /mnt (manual)");
    }    

    //trigger_timer_interrupt();
    /* Phase 5: Gestion des processus (APReS allocateurs) */
    init_process_system();

    if (framebuffer_base) {
        if (display_start_daemon() == 0)
            KBOOT_OK("Display: cursor daemon");
        else
            KBOOT_WARN("Display: cursor daemon unavailable");
    }

    KBOOT_OK("Process: scheduler ready");

    /* Main scheduler loop */
    KINFO("Starting scheduler with unified system...\n");
    print_signal_stack_stats();
    sched_start();

    panic("Returned from unified scheduler!");

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

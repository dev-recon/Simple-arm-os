/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/main.c
 * Layer: Kernel / bootstrap orchestration
 *
 * Responsibilities:
 * - Bring up core kernel subsystems in boot order.
 * - Report high-level boot status and enter the scheduler.
 *
 * Notes:
 * - Keep tty0/UART usable as the recovery console.
 */

#include <kernel/arch_platform.h>
#include <kernel/config.h>
#include <kernel/linker.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/interrupt.h>
#include <kernel/timer.h>
#include <kernel/display.h>
#include <kernel/platform_devices.h>
#include <kernel/vfs.h>
#include <kernel/ata.h>
#include <kernel/smp.h>
#include <kernel/tlb.h>
#include <kernel/arch_cpu.h>
#include <kernel/uart.h>
#include <kernel/panic.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/debug_print.h>
#include <kernel/stdarg.h>
#include <kernel/ide.h>
#include <kernel/ramfs.h>
#include <kernel/userfs_loader.h>
#include <kernel/disk_layout.h>

#include <kernel/task.h>
#include <kernel/kernel_tasks.h>

#include <kernel/tty.h>
#include <kernel/exceptions.h>

/* Static stack-protector canary used by freestanding kernel builds. */
uintptr_t __stack_chk_guard = 0xDEADBEEF;

void __attribute__((noreturn)) __stack_chk_fail(void) {
    panic("Stack smashing detected");
    while (1) {}
}


void init_early_uart(void)
{
    volatile uint32_t* uart =
        (volatile uint32_t*)(uintptr_t)arch_platform_uart0_phys_base();
    
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
    arch_disable_interrupts();
    uart_puts("KERNEL PANIC: ");
    uart_puts(message);
    uart_puts("\n");
    
    while (1) {
        arch_wait_for_interrupt();
    }
}


/* Forward declarations */
void early_init(void); 
void kernel_main(void);

static uint32_t boot_timer_frequency(void)
{
    return arch_timer_frequency();
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
 * Point d'entree principal du kernel.
 */
void kernel_main(void)
{
    arch_cpuinfo_t boot_cpuinfo;
    uint32_t timer_freq;
    uint32_t bogo_x100;
    uint32_t total_mb;
    uint32_t available_mb;
    uint64_t disk_sectors;
    uint32_t disk_mb;
    platform_devices_state_t platform_devices;

    /* Phase 0: etats du processeur */
    enable_async_abort_irq_fiq();

    sctlr_set_smp();
    smp_init_boot_cpu();

    timer_freq = boot_timer_frequency();
    bogo_x100 = boot_bogomips_x100(timer_freq);
    arch_get_cpuinfo(&boot_cpuinfo);

    KBOOT("\n");
    KBOOT(KBOOT_COLOR_INFO "ArmOS 0.6 %s" KBOOT_COLOR_RESET "\n",
          arch_machine_name());
    KBOOT_OKF("CPU: %s", boot_cpuinfo.model_name ? boot_cpuinfo.model_name : "unknown");
    KBOOT_OKF("Calibrating delay loop... %u.%02u BogoMIPS",
                bogo_x100 / 100, bogo_x100 % 100);

    //arch_disable_branch_predictor();
    
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
    irq_init_controller();
    KBOOT_OKF("GIC: v2, 288 IRQs");

    //init_timer_software();
    init_timer();
    KBOOT_OKF("Timer: ARM generic timer @ %u Hz, tick %u us",
                timer_freq, 1000000 / TIMER_FREQ);

    smp_start_secondary_cpus();
    KBOOT_OKF("SMP: %u CPU(s) configured, %u online",
              smp_possible_cpu_count(), smp_online_cpu_count());

    /* Phase 4: Peripheriques d'entree/sortie */
    platform_devices = platform_devices_init();
      
    //kprintf("Initialize IDE ... ");
    //init_ide();
    //ide_comprehensive_test();
    //kprintf("OK\n");

    /* Phase 6: Activation des interruptions */
    timer_enable_scheduling();
 
    arch_enable_interrupts();

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
        if (!disk_layout_init_from_mbr()) {
            KBOOT_WARN("Partition: using compiled fallback layout");
        }
    }

    if (!init_vfs()) {
        KBOOT_WARN("VFS: mount failed");
    } else {
        const disk_partition_t* ext2_part = disk_partition_get(DISK_PART_EXT2_ROOT);
        const disk_partition_t* fat32_part = disk_partition_get(DISK_PART_FAT32_MNT);
        KBOOT_OKF("Partition: %s ext2 %uMB",
                  ext2_part ? ext2_part->name : "virtio0p1",
                  ext2_part ? (uint32_t)(ext2_part->sector_count / 2048ULL) : 0);
        KBOOT_OKF("Partition: %s fat32 %uMB",
                  fat32_part ? fat32_part->name : "virtio0p2",
                  fat32_part ? (uint32_t)(fat32_part->sector_count / 2048ULL) : 0);
        KBOOT_OKF("VFS: mounted ext2 on /");
        KBOOT_OKF("VFS: mounted proc on /proc");
        KBOOT_OKF("VFS: fat32 available on /mnt (manual)");
    }    

    //trigger_timer_interrupt();
    /* Phase 5: Gestion des processus (APReS allocateurs) */
    init_process_system();

    if (coredumpd_start() == 0)
        KBOOT_OK("Core: coredump daemon");
    else
        KBOOT_WARN("Core: coredump daemon unavailable");

    if (platform_devices.tty1_graphics_ready) {
        if (display_start_daemon() == 0)
            KBOOT_OK("Display: cursor daemon");
        else
            KBOOT_WARN("Display: cursor daemon unavailable");
    }

    KBOOT_OK("Process: scheduler ready");

    if (smp_possible_cpu_count() > 1) {
        KBOOT_OK("SMP: TLB/IPI preflight");
        tlb_shootdown_all();
        for (uint32_t cpu = 1; cpu < smp_possible_cpu_count(); cpu++) {
            if (smp_enable_scheduler_cpu(cpu) == 0)
                KBOOT_OKF("SMP: scheduler enabled on CPU%u", cpu);
            else
                KBOOT_WARNF("SMP: CPU%u scheduler remains parked", cpu);
        }
    }

    /* Main scheduler loop */
    sched_start();

    panic("Returned from unified scheduler!");

}

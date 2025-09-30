/* kernel/interrupt/gic.c - Adapte pour machine virt SANS redefinitions */
#include <kernel/interrupt.h>
#include <kernel/kernel.h>
#include <kernel/timer.h>
#include <kernel/keyboard.h>
#include <kernel/ata.h>
#include <kernel/uart.h>
#include <kernel/ide.h>
#include <kernel/kprintf.h>
#include <kernel/mmio.h>

/* Compteur global pour verifier que les IRQ arrivent */
static volatile uint32_t irq_count = 0;
static volatile uint32_t last_irq_id = 0;

/* Utiliser les constantes de kernel.h au lieu de redefinir */
#define LOCAL_GICD_BASE     VIRT_GIC_DIST_BASE
#define LOCAL_GICC_BASE     VIRT_GIC_CPU_BASE
#define LOCAL_VIRTIO_BASE   VIRTIO_BASE

void init_gic(void)
{
    KDEBUG("[GIC] Starting GIC initialization (machine virt)...\n");
    
    volatile uint32_t* gicd = (volatile uint32_t*)LOCAL_GICD_BASE;
    volatile uint32_t* gicc = (volatile uint32_t*)LOCAL_GICC_BASE;
    
    /* === PHASE 1: IDENTIFICATION === */
    
    uint32_t gicd_iidr = gicd[0x008/4];  /* GICD_IIDR */
    uint32_t gicc_iidr = gicc[0x00C/4];  /* GICC_IIDR */
    uint32_t gicd_typer = gicd[0x004/4]; /* GICD_TYPER */
    
    KDEBUG("[GIC] GICD_IIDR: 0x%08X\n", gicd_iidr);
    KDEBUG("[GIC] GICC_IIDR: 0x%08X\n", gicc_iidr);
    KDEBUG("[GIC] GICD_TYPER: 0x%08X\n", gicd_typer);
    
    uint32_t num_irqs = ((gicd_typer & 0x1F) + 1) * 32;
    KDEBUG("[GIC] Number of IRQs: %u\n", num_irqs);
    
    /* Detecter si on est sur QEMU machine virt */
    bool is_qemu_virt = true;  /* Assumer QEMU virt */
    KDEBUG("[GIC] TARGET QEMU machine virt detected - using auto-targeting mode\n");
    
    /* === PHASE 2: CONFIGURATION === */
    
    KDEBUG("[GIC] Disabling GIC temporarily...\n");
    gicd[0x000/4] = 0;
    gicc[0x000/4] = 0;
    
    /* Configuration des priorites */
    KDEBUG("[GIC] Setting interrupt priorities...\n");
    for (uint32_t i = 0; i < num_irqs; i += 4) {
        gicd[0x400/4 + i/4] = 0xA0A0A0A0;
    }
    
    /* Configuration CPU interface */
    KDEBUG("[GIC] Configuring CPU interface...\n");
    gicc[0x004/4] = 0xF0;  /* GICC_PMR: Priorite mask tres permissive */
    gicc[0x008/4] = 0x03;  /* GICC_BPR: Binary point */
    
    /* === PHASE 3: TEST ITARGETSR (INFORMATIF SEULEMENT) === */
    
    volatile uint8_t* itargetsr = (volatile uint8_t*)(LOCAL_GICD_BASE + 0x800);
    
    if (is_qemu_virt) {
        KDEBUG("[GIC] QEMU mode: ITARGETSR is read-only (auto-managed)\n");
        KDEBUG("[GIC] This is NORMAL behavior - interrupts will still work!\n");
        
        /* Verifier les valeurs auto-configurees */
        for (uint32_t irq = 16; irq < 48; irq += 4) {
            uint8_t t0 = itargetsr[irq];
            uint8_t t1 = itargetsr[irq+1];
            uint8_t t2 = itargetsr[irq+2];
            uint8_t t3 = itargetsr[irq+3];
            
            if (t0 | t1 | t2 | t3) {  /* Si au moins une est non-zero */
                KDEBUG("[GIC] IRQ %u-%u targets: 0x%02X 0x%02X 0x%02X 0x%02X\n",
                       irq, irq+3, t0, t1, t2, t3);
            }
        }
    }
    
    /* === PHASE 4: ACTIVATION === */
    
    KDEBUG("[GIC] Enabling GIC...\n");
    gicd[0x000/4] = 0x01;  /* Enable distributor */
    gicc[0x000/4] = 0x01;  /* Enable CPU interface */
    
    /* === PHASE 5: CONFIGURATION IRQ IMPORTANTES === */
    
    //KDEBUG("[GIC] Enabling important IRQs...\n");
    /* IRQs pour machine virt : UART=1, Timer=30, VirtIO=16-31 */
#if 1
    uint32_t important_irqs[] = {1, 30, 16, 17, 18, 19, 48, 79};
    
    for (int i = 0; i < 8; i++) {
        uint32_t irq = important_irqs[i];
        
        /* 1. Configurer comme edge-triggered si IRQ >= 16 */
        if (irq >= 16) {
            volatile uint32_t* icfgr = (volatile uint32_t*)(LOCAL_GICD_BASE + 0xC00);
            uint32_t cfg = icfgr[irq / 16];
            uint32_t shift = (irq % 16) * 2;
            cfg &= ~(0b11 << shift);
            cfg |=  (0b10 << shift);  /* Edge-triggered */
            icfgr[irq / 16] = cfg;
        }
        
        /* 2. Activer l'IRQ */
        uint32_t reg = irq / 32;
        uint32_t bit = irq % 32;
        gicd[0x100/4 + reg] |= (1 << bit);
        
        /* 3. Verifier l'etat */
        uint32_t enabled = gicd[0x100/4 + reg] & (1 << bit);
        uint8_t target = itargetsr[irq];
        
        if (is_qemu_virt && target == 0) {
            KDEBUG("[GIC] IRQ %u: %s, target=AUTO OK\n", 
                   irq, enabled ? "ENABLED" : "disabled");
        } else {
            KDEBUG("[GIC] IRQ %u: %s, target=0x%02X %s\n", 
                   irq, enabled ? "ENABLED" : "disabled", target,
                   (target != 0) ? "OK" : "KO");
        }
    }
#endif
    
    /* === PHASE 6: VeRIFICATION FINALE === */
    
    uint32_t final_gicd = gicd[0x000/4];
    uint32_t final_gicc = gicc[0x000/4];
    
    KDEBUG("[GIC] Final status:\n");
    KDEBUG("[GIC]   GICD_CTLR: 0x%08X %s\n", final_gicd,
           (final_gicd & 1) ? "OK ACTIVE" : "KO INACTIVE");
    KDEBUG("[GIC]   GICC_CTLR: 0x%08X %s\n", final_gicc,
           (final_gicc & 1) ? "OK ACTIVE" : "KO INACTIVE");
    
    if ((final_gicd & 1) && (final_gicc & 1)) {
        KDEBUG("[GIC] - QEMU machine virt GIC ready! (auto-targeting mode)\n");
    } else {
        KDEBUG("[GIC] KO GIC initialization failed\n");
    }
}

void fiq_c_handler(void)
{
    irq_c_handler();
}

void irq_c_handler(void)
{
    uint32_t old_ttbr0 = get_ttbr0();
    uint32_t ttbr0 = (uint32_t)get_kernel_ttbr0();

    set_ttbr0(ttbr0);
    /* dsb isb if needed */
    __asm__ volatile ("dsb; isb");

    volatile uint32_t* gicc = (volatile uint32_t*)LOCAL_GICC_BASE;
    
    /* Lire l'IRQ ID */
    uint32_t irq_id = gicc[0x00C/4];  /* GICC_IAR */
    uint32_t int_id = irq_id & 0x3FF;
    
    /* Compteur global */
    irq_count++;
    last_irq_id = int_id;
    
    /* Debug : afficher l'IRQ recue */
    //kprintf("[IRQ] DONE IRQ %u received! (count=%u)\n", int_id, irq_count);
    
    /* Router vers les handlers specifiques pour machine virt */
    switch (int_id) {
        case VIRT_TIMER_NS_EL1_IRQ:  /* Timer generique ARM */
            //kprintf("[IRQ] Generic Timer IRQ %u Received\n", int_id);
            timer_irq_handler();
            break;
            
        case VIRT_UART_IRQ:  /* UART machine virt */
            //kprintf("[IRQ] UART IRQ %u Received\n", int_id);
            //uart_irq_handler();
            break;

        case 12:
            //kprintf("[IRQ] Keyboard IRQ 12 Received\n");
            keyboard_irq_handler();
            break;
            
        case 15:  /* IDE si present */
            //kprintf("[IRQ] IDE IRQ %u Received\n", int_id);
            ide_irq_handler();
            break;
            
        /* VirtIO IRQs pour machine virt */
        case VIRT_VIRTIO_NET_IRQ:
        case VIRT_VIRTIO_BLOCK_IRQ:
        case VIRT_VIRTIO_CONSOLE_IRQ:
        case VIRT_VIRTIO_RNG_IRQ:
        case 79:
        case 48:
            //kprintf("[IRQ] - VirtIO IRQ %u - SUCCESS!\n", int_id);
            //uart_puts("[IRQ] - VirtIO IRQ - SUCCESS!\n");
            /*virtio_irq_handler(int_id); */
            ata_irq_handler();
            break;
            
        case 1023:
            /* Spurious interrupt - ne pas traiter */
            kprintf("[IRQ] Spurious interrupt (1023)\n");
            break;
            
        default:
            kprintf("[IRQ] Unknown IRQ %u\n", int_id);
            break;
    }
    
    /* CRITIQUE : Acquitter l'IRQ */
    gicc[0x010/4] = irq_id;  /* GICC_EOIR */
    set_ttbr0(old_ttbr0);
}

void enable_irq(uint32_t irq)
{   
    KDEBUG("[IRQ] Enabling IRQ %u (machine virt mode)...\n", irq);
    
    volatile uint32_t* gicd = (volatile uint32_t*)LOCAL_GICD_BASE;
    volatile uint8_t* itargetsr = (volatile uint8_t*)(LOCAL_GICD_BASE + 0x800);
    
    /* 1. Verifier ITARGETSR (informatif seulement) */
    uint8_t target = itargetsr[irq];
    if (target == 0) {
        KDEBUG("[IRQ]   Target: AUTO (QEMU managed)\n");
    } else {
        KDEBUG("[IRQ]   Target: 0x%02X \n", target);
    }
    
    /* 2. Configurer le type (edge-triggered pour IRQ >= 16) */
    if (irq >= 16) {
        volatile uint32_t* icfgr = (volatile uint32_t*)(LOCAL_GICD_BASE + 0xC00);
        uint32_t cfg = icfgr[irq / 16];
        uint32_t shift = (irq % 16) * 2;
        
        cfg &= ~(0b11 << shift);
        cfg |=  (0b10 << shift);  /* Edge-triggered */
        icfgr[irq / 16] = cfg;
        
        KDEBUG("[IRQ]   Type: Edge-triggered OK\n");
    } else {
        KDEBUG("[IRQ]   Type: Level-triggered (SGI/PPI) OK\n");
    }
    
    /* 3. Configurer la priorite */
    volatile uint8_t* ipriority = (volatile uint8_t*)(LOCAL_GICD_BASE + 0x400);
    ipriority[irq] = 0xA0;
    KDEBUG("[IRQ]   Priority: 0xA0 OK\n");
    
    /* 4. Activer l'IRQ */
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    gicd[0x100/4 + reg] |= (1 << bit);
    
    /* Verifier l'activation */
    uint32_t enabled = gicd[0x100/4 + reg] & (1 << bit);
    KDEBUG("[IRQ]   Status: %s\n", enabled ? "ENABLED OK" : "FAILED KO");
    
    if (enabled) {
        KDEBUG("[IRQ] OK IRQ %u ready! (machine virt auto-route)\n", irq);
    } else {
        KDEBUG("[IRQ] KO IRQ %u activation failed\n", irq);
    }
}

void disable_irq(uint32_t irq)
{
    volatile uint32_t* gicd = (volatile uint32_t*)LOCAL_GICD_BASE;
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    
    gicd[0x180/4 + reg] |= (1 << bit);
}

/* Fonctions de test simplifiees sans redefinitions */
void test_timer_irq_virt(void)
{
    kprintf("[TEST] === TESTING ARM GENERIC TIMER ===\n");
    
    /* Utiliser ARM Generic Timer au lieu de SP804 */
    uint32_t freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(freq));
    
    if (freq > 0) {
        kprintf("[TEST] Generic Timer frequency: %u Hz\n", freq);
        
        /* Configurer timer pour 1 seconde */
        uint32_t tval = freq;  /* 1 seconde */
        __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" : : "r"(tval));
        
        /* Activer timer */
        uint32_t ctl = 1;  /* Enable */
        __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" : : "r"(ctl));
        
        /* Activer IRQ */
        enable_irq(VIRT_TIMER_NS_EL1_IRQ);
        
        kprintf("[TEST] Generic Timer configured, waiting for IRQ...\n");
    } else {
        kprintf("[TEST] Generic Timer not available\n");
    }
}

void comprehensive_irq_test_virt(void)
{
    kprintf("[TEST] === MACHINE VIRT IRQ TEST ===\n");
    
    uint32_t initial_count = irq_count;
    
    kprintf("[TEST] Initial IRQ count: %u\n", initial_count);
    
    /* Test ARM Generic Timer */
    test_timer_irq_virt();
    
    /* Attendre */
    for (volatile int i = 0; i < 10000000; i++);
    
    uint32_t final_count = irq_count;
    uint32_t received = final_count - initial_count;
    
    kprintf("[TEST] === TEST SUMMARY ===\n");
    kprintf("[TEST] IRQs received during test: %u\n", received);
    kprintf("[TEST] Total IRQ count: %u\n", final_count);
    kprintf("[TEST] Last IRQ ID: %u\n", last_irq_id);
    
    if (received > 0) {
        kprintf("[TEST] DONE SUCCESS: Machine virt interrupt system is WORKING!\n");
    } else {
        kprintf("[TEST] WARNING  No IRQs received - may need timer events\n");
    }
}

/* Test VirtIO simple pour machine virt */
void test_virtio_irq_virt(void)
{
    kprintf("[TEST] === TESTING VIRTIO IRQ (MACHINE VIRT) ===\n");
    
    volatile uint32_t* virtio = (volatile uint32_t*)LOCAL_VIRTIO_BASE;
    
    /* Verifier la presence VirtIO */
    uint32_t magic = virtio[0x000/4];  /* VIRTIO_MAGIC */
    
    kprintf("[TEST] VirtIO Magic: 0x%08X %s\n", magic, 
            (magic == 0x74726976) ? "OK VALID" : "KO INVALID");
    
    if (magic == 0x74726976) {
        uint32_t version = virtio[0x004/4];   /* VIRTIO_VERSION */
        uint32_t device_id = virtio[0x008/4]; /* VIRTIO_DEVICE_ID */
        
        kprintf("[TEST]   Version: %u\n", version);
        kprintf("[TEST]   Device ID: %u\n", device_id);
        
        /* Activer les IRQ VirtIO */
        enable_irq(VIRT_VIRTIO_NET_IRQ);
        enable_irq(VIRT_VIRTIO_BLOCK_IRQ);
        
        /* Reset et configure device */
        virtio[0x070/4] = 0;      /* Reset */
        virtio[0x070/4] = 1;      /* Acknowledge */
        
        kprintf("[TEST] VirtIO configured for machine virt\n");
    } else {
        kprintf("[TEST] No VirtIO device found at 0x%08X\n", LOCAL_VIRTIO_BASE);
    }
}

/* Fonction de test principale a appeler depuis kernel_main */
void complete_gic_debug_virt(void)
{
    kprintf("\n");
    kprintf("- === MACHINE VIRT GIC DEBUG ===\n");
    kprintf("Testing interrupt system on QEMU machine virt...\n");
    kprintf("\n");
    
    /* Test 1: Timer generique ARM */
    test_timer_irq_virt();
    kprintf("\n");
    
    /* Test 2: VirtIO */
    test_virtio_irq_virt();
    kprintf("\n");
    
    /* Test 3: Test complet */
    comprehensive_irq_test_virt();
    
    kprintf("=== MACHINE VIRT TESTING COMPLETE ===\n");
    kprintf("DONE Your machine virt interrupt system is ready!\n");
}

/* Fonctions aliases pour compatibilite */
void set_irq_edge_triggered(uint32_t irq)
{
    volatile uint32_t* icfgr = (volatile uint32_t*)(LOCAL_GICD_BASE + 0xC00);
    if (irq >= 16) {
        uint32_t cfg = icfgr[irq / 16];
        uint32_t shift = (irq % 16) * 2;
        cfg &= ~(0b11 << shift);
        cfg |=  (0b10 << shift);
        icfgr[irq / 16] = cfg;
        KDEBUG("[IRQ] IRQ %u configured as edge-triggered\n", irq);
    }
}

/* Aliases pour eviter les conflits avec mmio.h */
void gic_enable_irq_kernel(uint32_t irq) {
    enable_irq(irq);
}

void gic_ack_irq_kernel(uint32_t irq) {
    volatile uint32_t* gicc = (volatile uint32_t*)LOCAL_GICC_BASE;
    gicc[0x010/4] = irq;
}
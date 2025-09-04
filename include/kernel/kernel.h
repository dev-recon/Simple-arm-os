/* include/kernel/kernel.h - Adapte pour machine QEMU virt */
#ifndef _KERNEL_H
#define _KERNEL_H

#include <kernel/types.h>
#include <kernel/string.h>

#define USE_RAMFS 1

uint32_t get_kernel_memory_size(void);

/* === INFORMATIONS DU LINKER SCRIPT === */

/* Symboles exportes par le linker script pour machine virt */
extern uint32_t __start;           /* Debut du kernel */
extern uint32_t __end;             /* Fin du kernel */
extern uint32_t __kernel_start;    /* Alias pour __start */
extern uint32_t __kernel_end;      /* Alias pour __end */
extern uint32_t __kernel_size;     /* Taille du kernel */

/* Sections du kernel */
extern uint32_t __text_start;      /* Debut section .text */
extern uint32_t __text_end;        /* Fin section .text */
extern uint32_t __rodata_start;    /* Debut section .rodata */
extern uint32_t __rodata_end;      /* Fin section .rodata */
extern uint32_t __data_start;      /* Debut section .data */
extern uint32_t __data_end;        /* Fin section .data */
extern uint32_t __bss_start;       /* Debut section .bss */
extern uint32_t __bss_end;         /* Fin section .bss */

//extern uint32_t __mmu_tables_start;
//extern uint32_t __mmu_tables_end;
//extern uint32_t __mmu_size;

/* Pile et heap kernel */
extern uint32_t __stack_bottom;    /* Debut de la pile kernel */
extern uint32_t __stack_top;       /* Fin de la pile kernel */
extern uint32_t stack_bottom;      /* Alias */
extern uint32_t stack_top;         /* Alias */
extern uint32_t __heap_start;      /* Debut du heap kernel */
extern uint32_t __heap_end;        /* Fin du heap kernel */
extern uint32_t __heap_size;       /* Taille du heap kernel */
extern uint32_t __ram_start;       /* Debut RAM libre */
extern uint32_t __ram_end;         /* Fin RAM libre */
extern uint32_t __ram_size;        /* Taille RAM libre */
extern uint32_t __free_memory_start; /* Debut memoire libre */

extern uint32_t __stack_svc_top;

/* ========================================================================
 * CONSTANTES HARDWARE MACHINE VIRT
 * ======================================================================== */
#define VIRT_RAM_START          0x40000000u                    /* Debut RAM physique */
#define VIRT_RAM_SIZE           get_kernel_memory_size()        /* 4 GB */
#define VIRT_RAM_END            (VIRT_RAM_START + VIRT_RAM_SIZE)

/* Memory map machine virt */
#define VIRT_FLASH_BASE         0x00000000u                    /* Flash/ROM */
#define VIRT_FLASH_SIZE         0x08000000u                    /* 128MB */

/* GIC (Generic Interrupt Controller) v2 */
#define VIRT_GIC_DIST_BASE      0x08000000u                    /* Distributor */
#define VIRT_GIC_DIST_SIZE      0x00010000u                    /* 64KB */
#define VIRT_GIC_CPU_BASE       0x08010000u                    /* CPU interface */
#define VIRT_GIC_CPU_SIZE       0x00010000u                    /* 64KB */
#define VIRT_GIC_V2M_BASE       0x08020000u                    /* MSI controller */
#define VIRT_GIC_V2M_SIZE       0x00001000u                    /* 4KB */
#define VIRT_GIC_HYP_BASE       0x08030000u                    /* Hypervisor */
#define VIRT_GIC_HYP_SIZE       0x00010000u                    /* 64KB */
#define VIRT_GIC_VCPU_BASE      0x08040000u                    /* Virtual CPU */
#define VIRT_GIC_VCPU_SIZE      0x00010000u                    /* 64KB */

/* Peripheriques systeme machine virt */
#define VIRT_UART_BASE          0x09000000u                    /* PL011 UART */
#define VIRT_UART_SIZE          0x00001000u                    /* 4KB */
#define VIRT_UART_IRQ           1                             /* IRQ 1 */

#define VIRT_RTC_BASE           0x09010000u                    /* PL031 RTC */
#define VIRT_RTC_SIZE           0x00001000u                    /* 4KB */
#define VIRT_RTC_IRQ            2                             /* IRQ 2 */

#define VIRT_FW_CFG_BASE        0x09020000u                    /* Firmware config */
#define VIRT_FW_CFG_SIZE        0x00000018u                    /* 24 bytes */

#define VIRT_GPIO_BASE          0x09030000u                    /* PL061 GPIO */
#define VIRT_GPIO_SIZE          0x00001000u                    /* 4KB */
#define VIRT_GPIO_IRQ           7                             /* IRQ 7 */

#define VIRT_SECURE_UART_BASE   0x09040000u                    /* Secure UART */
#define VIRT_SECURE_UART_SIZE   0x00001000u                    /* 4KB */

/* VirtIO devices MMIO region */
#define VIRT_VIRTIO_BASE        0x0A000000u                    /* VirtIO devices */
#define VIRT_VIRTIO_SIZE        0x00000200u                    /* 512 bytes per device */
#define VIRT_VIRTIO_IRQ_BASE    16                            /* IRQ 16+ */

/* Alias pour compatibilite avec votre code existant */
#define VIRTIO_BASE             VIRT_VIRTIO_BASE              /* 0x0A000000 */
#define VIRTIO_SIZE             VIRT_VIRTIO_SIZE              /* 512 bytes per device */
#define VIRTIO_IRQ_BASE         VIRT_VIRTIO_IRQ_BASE          /* IRQ 16+ */

/* Calcul des adresses VirtIO individuelles */
#define VIRT_VIRTIO_DEVICE(n)   (VIRT_VIRTIO_BASE + (n) * VIRT_VIRTIO_SIZE)
#define VIRT_VIRTIO_IRQ(n)      (VIRT_VIRTIO_IRQ_BASE + (n))

/* Peripheriques VirtIO typiques */
#define VIRT_VIRTIO_NET         VIRT_VIRTIO_DEVICE(0)         /* Reseau */
#define VIRT_VIRTIO_BLOCK       VIRT_VIRTIO_DEVICE(1)         /* Stockage */
#define VIRT_VIRTIO_CONSOLE     VIRT_VIRTIO_DEVICE(2)         /* Console */
#define VIRT_VIRTIO_RNG         VIRT_VIRTIO_DEVICE(3)         /* RNG */

#define VIRT_VIRTIO_NET_IRQ     VIRT_VIRTIO_IRQ(0)            /* IRQ 16 */
#define VIRT_VIRTIO_BLOCK_IRQ   VIRT_VIRTIO_IRQ(1)            /* IRQ 17 */
#define VIRT_VIRTIO_CONSOLE_IRQ VIRT_VIRTIO_IRQ(2)            /* IRQ 18 */
#define VIRT_VIRTIO_RNG_IRQ     VIRT_VIRTIO_IRQ(3)            /* IRQ 19 */

/* Macros pour acceder aux peripheriques VirtIO */
#define VIRTIO_DEVICE(n)        VIRT_VIRTIO_DEVICE(n)
#define VIRTIO_IRQ(n)           VIRT_VIRTIO_IRQ(n)

/* PCI Configuration Space */
#define VIRT_PCIE_MMIO_BASE     0x10000000u                    /* PCI MMIO */
#define VIRT_PCIE_MMIO_SIZE     0x2EFF0000u                    /* 752MB */
#define VIRT_PCIE_PIO_BASE      0x3EFF0000u                    /* PCI I/O */
#define VIRT_PCIE_PIO_SIZE      0x00010000u                    /* 64KB */
#define VIRT_PCIE_ECAM_BASE     0x3F000000u                    /* ECAM space */
#define VIRT_PCIE_ECAM_SIZE     0x01000000u                    /* 16MB */

/* Timers ARM Generic pour machine virt */
#define VIRT_TIMER_NS_EL1_IRQ   30                            /* Non-secure EL1 */
#define VIRT_TIMER_S_EL1_IRQ    29                            /* Secure EL1 */
#define VIRT_TIMER_HYP_IRQ      26                            /* Hypervisor */
#define VIRT_TIMER_VIRT_IRQ     27                            /* Virtual */

/* Tailles de page */
#define PAGE_SIZE               4096
#define PAGE_SHIFT              12
#define PAGE_OFFSET_MASK        0x00000FFFu
#define PAGE_MASK               0xFFFFF000u

/* ========================================================================
 * KERNEL SPACE (utilise les symboles du linker)
 * ======================================================================== */
#define KERNEL_START            ((uint32_t)&__start)          /* Debut kernel */
#define KERNEL_END              ((uint32_t)&__end)            /* Fin kernel */
#define KERNEL_SIZE             ((uint32_t)&__kernel_size)    /* Taille kernel */
#define KERNEL_BASE             KERNEL_START                  /* Alias compatibilite */

/* Sections kernel */
#define KERNEL_TEXT_START       ((uint32_t)&__text_start)
#define KERNEL_TEXT_END         ((uint32_t)&__text_end)
#define KERNEL_DATA_START       ((uint32_t)&__data_start)
#define KERNEL_DATA_END         ((uint32_t)&__data_end)
#define KERNEL_BSS_START        ((uint32_t)&__bss_start)
#define KERNEL_BSS_END          ((uint32_t)&__bss_end)

/* Stack kernel */
#define KERNEL_STACK_BOTTOM     ((uint32_t)&__stack_bottom)
#define KERNEL_STACK_TOP        ((uint32_t)&__stack_top)
#define KERNEL_STACK_SIZE       (KERNEL_STACK_TOP - KERNEL_STACK_BOTTOM)

/* Heap kernel (defini par le linker) */
#define KERNEL_HEAP_START       ((uint32_t)&__heap_start)
#define KERNEL_HEAP_END         ((uint32_t)&__heap_end)
#define KERNEL_HEAP_SIZE        ((uint32_t)&__heap_size)

/* RAM physique disponible (apres kernel et heap) */
#define PHYSICAL_RAM_START      ((uint32_t)&__ram_start)
#define PHYSICAL_RAM_END        ((uint32_t)&__ram_end)
#define PHYSICAL_RAM_SIZE       ((uint32_t)&__ram_size)
#define FREE_MEMORY_START       ((uint32_t)&__free_memory_start)

#define KERNEL_SVC_STACK_TOP    ((uint32_t)&__stack_svc_top)

/* Aliases pour compatibilite */
#define HEAP_START              KERNEL_HEAP_START
#define HEAP_END                KERNEL_HEAP_END
#define HEAP_SIZE               KERNEL_HEAP_SIZE
#define RAM_START               PHYSICAL_RAM_START
#define RAM_END                 PHYSICAL_RAM_END
#define RAM_SIZE                PHYSICAL_RAM_SIZE

/* Bits des entrees de page directory (niveau 1) */
#define PDE_TYPE_MASK           0x3
#define PDE_TYPE_FAULT          0x0
#define PDE_TYPE_COARSE         0x1
#define PDE_TYPE_SECTION        0x2

/* Bits pour les sections (1MB) */
#define PDE_SECTION_BASE        0xFFF00000u
#define PDE_AP_MASK             0xC00
#define PDE_AP_RW_RW            0x400                         /* Read/Write pour user et kernel */
#define PDE_AP_RW_NA            0x800                         /* Read/Write kernel, No Access user */
#define PDE_DOMAIN_MASK         0x1E0
#define PDE_DOMAIN(x)           ((x) << 5)
#define PDE_CACHEABLE           0x8                           /* Bit C */
#define PDE_BUFFERABLE          0x4                           /* Bit B */

/* === ADRESSES HARDWARE MACHINE VIRT === */

/* UART (PL011) - compatible avec machine virt */
#define UART0_BASE              VIRT_UART_BASE                /* UART0 machine virt */
#define UART1_BASE              (VIRT_UART_BASE + 0x1000)    /* UART1 hypothetique */
#define UART2_BASE              (VIRT_UART_BASE + 0x2000)    /* UART2 hypothetique */
#define UART3_BASE              (VIRT_UART_BASE + 0x3000)    /* UART3 hypothetique */

/* Interrupt Controller (GIC) */
#define GIC_DIST_BASE           VIRT_GIC_DIST_BASE            /* GIC Distributor */
#define GIC_CPU_BASE            VIRT_GIC_CPU_BASE             /* GIC CPU Interface */

/* Timer (ARM Generic Timer) */
#define TIMER0_BASE             0x09000000u                    /* Pas utilise sur virt */
#define TIMER1_BASE             0x09000000u                    /* Pas utilise sur virt */

/* GPIO */
#define GPIO0_BASE              VIRT_GPIO_BASE                /* GPIO Port 0 */
#define GPIO1_BASE              (VIRT_GPIO_BASE + 0x1000)    /* GPIO Port 1 hypothetique */

/* RTC */
#define RTC_BASE                VIRT_RTC_BASE                 /* PL031 RTC */

/* Regions de peripheriques */
#define DEVICE_START            0x08000000u                    /* Debut peripheriques */
#define DEVICE_END              0x40000000u                    /* Fin peripheriques */
#define PERIPHERAL_START        0x08000000u                    /* Debut peripheriques */
#define PERIPHERAL_END          0x40000000u                    /* Fin peripheriques */

/* ========================================================================
 * USER SPACE - PReSERVE VOS CONSTANTES EXISTANTES
 * ======================================================================== */

/*
 * LAYOUT ACTUEL (preserve) mais avec signal stack optimisee pour machine virt :
 * 
 * 0x00000000 - 0x00010000  : Reserve systeme
 * 0x00010000 - 0x08000000  : Code et donnees utilisateur (127MB)
 * 0x08000000 - 0x37000000  : Heap utilisateur (votre taille actuelle)
 * 0x37000000 - 0x3F000000  : Stack utilisateur (8MB - votre taille)
 * 0x3F000000 - 0x40000000  : Zone libre pour signal stacks (16MB)
 * 0x40000000+              : Kernel space (machine virt)
 */



/* Zones memoire utilisateur - VOS CONSTANTES PReSERVeES */
#define USER_SPACE_START        0x00010000u                    /* Debut espace utilisateur */
#define USER_STACK_TOP          0x3F000000u                    /* Pile utilisateur (avant kernel) */
#define USER_STACK_SIZE         (8*1024*1024u)                 /* 8MB de pile */
//#define USER_STACK_SIZE         (8*1024u)                       /* 8KB de pile */
#define USER_STACK_BOTTOM       (USER_STACK_TOP - USER_STACK_SIZE)  /* 0x37000000 */
#define USER_HEAP_START         0x08000000u                    /* Debut heap utilisateur */
#define USER_HEAP_END           USER_STACK_BOTTOM             /* 0x37000000 */
#define USER_SPACE_END          USER_STACK_TOP                /* 0x3F000000 */

/* Heap utilisateur - taille actuelle preservee */
#define USER_HEAP_MAX_SIZE      (USER_HEAP_END - USER_HEAP_START)  /* 752MB */

/* NOUVELLE : Zone dediee aux signal stacks APReS la stack user */
#define USER_SIGNAL_REGION_START USER_STACK_TOP               /* 0x3F000000 */
#define USER_SIGNAL_REGION_END   KERNEL_START                 /* Jusqu'au kernel (~0x40000000) */
#define USER_SIGNAL_REGION_SIZE  (USER_SIGNAL_REGION_END - USER_SIGNAL_REGION_START)  /* ~16MB */

/* ========================================================================
 * SIGNAL STACK - UTILISE LA ZONE LIBRE APReS USER_STACK_TOP
 * ======================================================================== */

/* Signal stack dans la zone libre entre user space et kernel */
#define DEFAULT_SIGNAL_STACK_SIZE   (16*1024u)                 /* 16KB par defaut */
#define MAX_SIGNAL_STACK_SIZE       (1024*1024u)               /* 1MB maximum */

/* Base pour signal stack (dans la zone libre de 16MB) */
#define SIGNAL_STACK_BASE_DEFAULT   (USER_SIGNAL_REGION_START + DEFAULT_SIGNAL_STACK_SIZE)

/* ========================================================================
 * MACROS UTILITAIRES
 * ======================================================================== */

/* Alignement de pages */
#define ALIGN_UP(x, align)      (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align)    ((x) & ~((align) - 1))

#define PAGE_ALIGN_UP(addr)     (((addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(addr)   ((addr) & PAGE_MASK)
#define IS_PAGE_ALIGNED(addr)   (((addr) & (PAGE_SIZE - 1)) == 0)

/* Verifications d'adresses pour machine virt */
//#define IS_KERNEL_ADDR(addr)    ((addr) >= KERNEL_START && (addr) < VIRT_RAM_END)
//#define IS_USER_ADDR(addr)      ((addr) >= USER_SPACE_START && (addr) < USER_SPACE_END)
#define IS_DEVICE_ADDR(addr)    ((addr) >= DEVICE_START && (addr) < DEVICE_END)
#define IS_VALID_RAM(addr)      ((addr) >= VIRT_RAM_START && (addr) < VIRT_RAM_END)
#define IS_VIRTIO_ADDR(addr)    ((addr) >= VIRT_VIRTIO_BASE && (addr) < (VIRT_VIRTIO_BASE + VIRT_VIRTIO_SIZE * 8))
#define IS_GIC_ADDR(addr)       ((addr) >= VIRT_GIC_DIST_BASE && (addr) < (VIRT_GIC_VCPU_BASE + VIRT_GIC_VCPU_SIZE))

/* Pages */
#define ADDR_TO_PAGE(addr)      ((addr) >> PAGE_SHIFT)
#define PAGE_TO_ADDR(page)      ((page) << PAGE_SHIFT)

/* Utilitaires */
#define MIN(a, b)               ((a) < (b) ? (a) : (b))
#define MAX(a, b)               ((a) > (b) ? (a) : (b))
#define ARRAY_SIZE(arr)         (sizeof(arr) / sizeof((arr)[0]))

/* Implemented in boot.S */
extern void PUT32(unsigned int, unsigned int);
extern unsigned int GET32(unsigned int);
extern void PUT8(unsigned int, unsigned int);  /* Compatible avec mmio.h */
extern unsigned int GET8(unsigned int);        /* Compatible avec mmio.h */
extern void PUT16(unsigned int, unsigned int); /* Compatible avec mmio.h */
extern unsigned int GET16(unsigned int);       /* Compatible avec mmio.h */


/* DTB structures */
struct fdt_header {
    uint32_t magic;           /* 0xd00dfeed */
    uint32_t totalsize;       
    uint32_t off_dt_struct;   
    uint32_t off_dt_strings;  
    uint32_t off_mem_rsvmap;  
    uint32_t version;         
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};

typedef struct {
    uint32_t cache_info;
    uint32_t tlb_info;
    uint32_t memory_model;
    uint32_t debug_features;
} cpu_memory_info_t;

#define FDT_MAGIC         0xd00dfeed
#define FDT_BEGIN_NODE    0x00000001
#define FDT_END_NODE      0x00000002
#define FDT_PROP          0x00000003
#define FDT_NOP           0x00000004
#define FDT_END           0x00000009

/* === FONCTIONS KERNEL === */

/* Panic et debug */
void panic(const char* message) __attribute__((noreturn));

/* Initialisation precoce */
void init_early_uart(void);
uint32_t detect_memory(void);

/* Informations du kernel */
static inline uint32_t get_kernel_start(void) { return KERNEL_START; }
static inline uint32_t get_kernel_end(void) { return KERNEL_END; }
static inline uint32_t get_kernel_size(void) { return KERNEL_SIZE; }

/* Informations des sections */
static inline uint32_t get_text_start(void) { return (uint32_t)&__text_start; }
static inline uint32_t get_text_end(void) { return (uint32_t)&__text_end; }
static inline uint32_t get_text_size(void) { 
    return (uint32_t)&__text_end - (uint32_t)&__text_start; 
}

static inline uint32_t get_data_start(void) { return (uint32_t)&__data_start; }
static inline uint32_t get_data_end(void) { return (uint32_t)&__data_end; }
static inline uint32_t get_data_size(void) { 
    return (uint32_t)&__data_end - (uint32_t)&__data_start; 
}

static inline uint32_t get_bss_start(void) { return (uint32_t)&__bss_start; }
static inline uint32_t get_bss_end(void) { return (uint32_t)&__bss_end; }
static inline uint32_t get_bss_size(void) { 
    return (uint32_t)&__bss_end - (uint32_t)&__bss_start; 
}

static inline uint32_t get_heap_start(void) { return (uint32_t)&__heap_start; }

/* Fonction de debug pour afficher le layout memoire */
void print_kernel_layout(void);

/* Supprimer les declarations en conflit avec mmio.h */
/* GIC (Generic Interrupt Controller) */
void gic_init(void);
void gic_enable_irq_kernel(uint32_t irq);  /* Renamed pour eviter conflit */
void gic_disable_irq(uint32_t irq);
uint32_t gic_get_active_irq(void);
void gic_ack_irq_kernel(uint32_t irq);     /* Renamed pour eviter conflit */

/* ARM Generic Timer */
void timer_init(void);
uint64_t timer_get_count(void);
uint32_t timer_get_frequency(void);

/* VirtIO support */
bool virtio_probe_device(uint32_t device_id);
void virtio_init(void);

/* Device Tree support */
void* get_dtb_address(void);
bool parse_device_tree(void);
void print_cpu_mode(void);

void* fdt_find_node_by_name(void* dtb_ptr, const char* node_name);
bool fdt_node_matches(const char* node_name, const char* prefix);
bool fdt_device_present(void* dtb_ptr, const char* partial_name);
void* fdt_get_property(void* dtb_ptr, void* node_ptr, const char* property_name, uint32_t* out_len);




/* === VeRIFICATIONS DE COMPATIBILITe === */

/* Verifier que les adresses sont coherentes */
#if VIRT_RAM_START != 0x40000000u
#error "VIRT_RAM_START must be 0x40000000 for machine virt"
#endif

#if PAGE_SIZE != 4096
#error "PAGE_SIZE must be 4096 for ARM32"
#endif

/* === ATTRIBUTS COMPILATEUR === */

/* Sections speciales */
#define __init_code             __attribute__((section(".text.init")))
#define __init_data             __attribute__((section(".data.init")))
#define __kernel_data           __attribute__((section(".data.kernel")))

/* Alignement ARM32 */
#define __aligned_4             __attribute__((aligned(4)))
#define __aligned_8             __attribute__((aligned(8)))
#define __aligned_page          __attribute__((aligned(PAGE_SIZE)))
#define __cache_aligned         __attribute__((aligned(64)))  /* Cache line Cortex-A15 */

/* Optimisations */
#define __always_inline         __attribute__((always_inline))
#define __noinline              __attribute__((noinline))
#define __pure                  __attribute__((pure))
#define __const                 __attribute__((const))

/* === CONSTANTES CORTEX-A15 === */

/* Cache line sizes */
#define L1_CACHE_LINE_SIZE      32
#define L2_CACHE_LINE_SIZE      64
#define CACHE_LINE_SIZE         L2_CACHE_LINE_SIZE

/* Performance features */
#define CORTEX_A15_FEATURES     1
#define HAS_NEON                1
#define HAS_VFP                 1
#define HAS_GENERIC_TIMER       1
#define HAS_LARGE_PHYS_ADDR     1

#define STDIN_FILENO            0
#define STDOUT_FILENO           1
#define STDERR_FILENO           2


static inline int sctlr_smp_enabled(void){
    uint32_t v; asm volatile("mrc p15,0,%0,c1,c0,0":"=r"(v));
    return (v >> 6) & 1;
}

static inline void sctlr_set_smp(void){
    uint32_t v;
    asm volatile("mrc p15,0,%0,c1,c0,0" : "=r"(v));
    v |= (1u << 6);                 // SMP=1
    asm volatile("mcr p15,0,%0,c1,c0,0" :: "r"(v) : "memory");
    asm volatile("isb; dsb sy");
}

static inline void tlb_flush_all_debug(void){
    asm volatile("dsb ish; mcr p15,0,%0,c8,c3,0; dsb ish; isb"::"r"(0):"memory"); // TLBIALlIS
}

static inline void dc_clean_mva(void *va) {
    asm volatile("mcr p15,0,%0,c7,c10,1"::"r"(va):"memory"); // DCCMVAC
}

static inline void dcache_clean_by_va(void *va, size_t len) {
    uintptr_t p   = (uintptr_t)va & ~63;
    uintptr_t end = ((uintptr_t)va + len + 63) & ~63;
    for (; p < end; p += 64)
        asm volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(p) : "memory"); // DCCMVAC
    asm volatile("dsb ish" ::: "memory");
}

static inline void sync_icache_for_exec(void) {
    asm volatile("mcr p15, 0, %0, c7, c5, 0" :: "r"(0)); // ICIALLU
    asm volatile("dsb ish; isb");
}

static inline int ats1cpr_probe(uint32_t va, uint32_t *pa_out, uint32_t *par_out){
    asm volatile("mcr p15,0,%0,c7,c8,0"::"r"(va));          // ATS1CPR
    uint32_t par; asm volatile("mrc p15,0,%0,c7,c4,0":"=r"(par));
    if (par_out) *par_out = par;
    if (par & 1) return 0;                                  // fault
    if (pa_out) *pa_out = (par & 0xFFFFF000u) | (va & 0xFFFu);
    return 1;
}

static inline uint32_t dcache_line_size_bytes(void) {
    uint32_t ccsidr;

    // Sélectionner L1 Data/Unified (Level=0, InD=0) dans CSSELR
    asm volatile ("mcr p15, 2, %0, c0, c0, 0" :: "r"(0) : "memory"); // CSSELR
    asm volatile ("isb");

    // Lire CCSIDR
    asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r"(ccsidr));

    uint32_t line_sz_enc = ccsidr & 0x7;                  // [2:0]
    uint32_t line_bytes  = 1u << (line_sz_enc + 4u);      // 4 * 2^(enc+2) = 1<<(enc+4)

    // Sécurité: sur A15 c’est 64, mais au cas où:
    if (line_bytes == 0 || line_bytes > 256) line_bytes = 64;
    return line_bytes;
}

// Clean D-cache by MVA to PoC sur une plage
static inline void clean_dcache_by_mva(const void *addr, size_t size) {
    if (size == 0) return;

    uint32_t line = dcache_line_size_bytes();
    uintptr_t start = ((uintptr_t)addr) & ~(uintptr_t)(line - 1u);
    uintptr_t end   = ((uintptr_t)addr + size + line - 1u) & ~(uintptr_t)(line - 1u);

    asm volatile("dsb ish" ::: "memory"); // s'assurer que toutes écritures précédentes sont visibles

    for (uintptr_t p = start; p < end; p += line) {
        asm volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(p) : "memory"); // DCCMVAC
    }

    asm volatile("dsb ish" ::: "memory"); // pousser les lignes nettoyées au PoC
}

// Invalidate D-cache by MVA sur une plage
static inline void invalidate_dcache_by_mva(const void *addr, size_t size) {
    if (size == 0) return;

    uint32_t line = dcache_line_size_bytes();
    uintptr_t start = ((uintptr_t)addr) & ~(uintptr_t)(line - 1u);
    uintptr_t end   = ((uintptr_t)addr + size + line - 1u) & ~(uintptr_t)(line - 1u);

    asm volatile("dsb ish" ::: "memory"); // finir les accès mémoire en cours

    for (uintptr_t p = start; p < end; p += line) {
        asm volatile("mcr p15, 0, %0, c7, c6, 1" :: "r"(p) : "memory"); // DCIMVAC
    }

    asm volatile("dsb ish" ::: "memory"); // garantir l’invalidation avant poursuite
}

// Optionnel: clean+invalidate en un seul passage (utile pour tests)
static inline void clean_invalidate_dcache_by_mva(const void *addr, size_t size) {
    if (size == 0) return;

    uint32_t line = dcache_line_size_bytes();
    uintptr_t start = ((uintptr_t)addr) & ~(uintptr_t)(line - 1u);
    uintptr_t end   = ((uintptr_t)addr + size + line - 1u) & ~(uintptr_t)(line - 1u);

    asm volatile("dsb ish" ::: "memory");

    for (uintptr_t p = start; p < end; p += line) {
        asm volatile("mcr p15, 0, %0, c7, c14, 1" :: "r"(p) : "memory"); // DCCIMVAC
    }

    asm volatile("dsb ish" ::: "memory");
}


static inline uint32_t read_sp_usr(void) {
    uint32_t sp;
    asm volatile(
        "cps #0x1F\n"     // SYS = mêmes banques que USR, mais privilègié
        "mov %0, sp\n"
        "cps #0x13\n"     // retour SVC
        : "=r"(sp) :: "memory","cc");
    return sp;
}

static inline void write_sp_usr(uint32_t sp) {
    asm volatile(
        "cps #0x1F\n"
        "mov sp, %0\n"
        "cps #0x13\n"
        :: "r"(sp) : "memory","cc");
}

static inline uint32_t read_spsr(void) { uint32_t v; asm volatile("mrs %0, spsr":"=r"(v)); return v; }
static inline uint32_t read_cpsr(void) { uint32_t v; asm volatile("mrs %0, cpsr":"=r"(v)); return v; }


static inline uint32_t read_spsr_svc(void) {
  uint32_t v; __asm__ volatile("mrs %0, spsr" : "=r"(v)); return v;
}
static inline uint32_t read_lr_svc(void) {
  uint32_t v; __asm__ volatile("mov %0, lr" : "=r"(v)); return v;
}

static inline uint32_t read_lr_usr(void) {
  uint32_t v; __asm__ volatile("cps #0x1F \n\t mov %0, lr \n\t cps #0x13" : "=r"(v) :: "memory"); return v;
}

#define offsetof(type, member) ((size_t)&((type*)0)->member)

//extern const uint32_t TASK_CONTEXT_OFF;

#endif /* _KERNEL_H */
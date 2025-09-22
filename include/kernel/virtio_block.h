/* kernel/include/kernel/virtio_block.h - VirtIO Block Device pour machine virt */
#ifndef _KERNEL_VIRTIO_BLOCK_H
#define _KERNEL_VIRTIO_BLOCK_H

#include <kernel/types.h>
//#include <kernel/kernel.h>

/* VirtIO Block Device - CORRECTION ADRESSE */
#define VIRTIO_BLK_IRQ      17  /* IRQ 17 pour machine virt */

/* Adresses VirtIO pour machine virt (depuis kernel.h) */
#define VIRTIO_BLOCK_BASE       VIRT_VIRTIO_BLOCK       /* 0x0A000200 */
#define VIRTIO_BLOCK_IRQ        VIRT_VIRTIO_BLOCK_IRQ   /* IRQ 17 */
#define VIRTIO_BLOCK_SIZE       VIRT_VIRTIO_SIZE        /* 512 bytes */

/* Registres VirtIO MMIO (offsets depuis base) */
#define VIRTIO_REG_MAGIC        0x000   /* Magic value */
#define VIRTIO_REG_VERSION      0x004   /* Version */
#define VIRTIO_REG_DEVICE_ID    0x008   /* Device ID */
#define VIRTIO_REG_VENDOR_ID    0x00C   /* Vendor ID */
#define VIRTIO_REG_HOST_FEAT    0x010   /* Host features */
#define VIRTIO_REG_HOST_FEAT_SEL 0x014  /* Host features select */
#define VIRTIO_REG_GUEST_FEAT   0x020   /* Guest features */
#define VIRTIO_REG_GUEST_FEAT_SEL 0x024 /* Guest features select */
#define VIRTIO_REG_GUEST_PAGE_SIZE 0x028 /* Guest page size (legacy) */
#define VIRTIO_REG_QUEUE_SEL    0x030   /* Queue select */
#define VIRTIO_REG_QUEUE_NUM_MAX 0x034  /* Queue num max */
#define VIRTIO_REG_QUEUE_NUM    0x038   /* Queue num */
#define VIRTIO_REG_QUEUE_ALIGN  0x03C   /* Queue align (legacy) */
#define VIRTIO_REG_QUEUE_PFN    0x040   /* Queue PFN (legacy) */
#define VIRTIO_REG_QUEUE_READY  0x044   /* Queue ready */
#define VIRTIO_REG_QUEUE_NOTIFY 0x050   /* Queue notify */
#define VIRTIO_REG_INTERRUPT_STATUS 0x060 /* Interrupt status */
#define VIRTIO_REG_INTERRUPT_ACK 0x064  /* Interrupt acknowledge */
#define VIRTIO_REG_STATUS       0x070   /* Device status */

/* VirtIO Device IDs */
#define VIRTIO_ID_NETWORK       1       /* Network card */
#define VIRTIO_ID_BLOCK         2       /* Block device */
#define VIRTIO_ID_CONSOLE       3       /* Console */
#define VIRTIO_ID_RNG           4       /* Random number generator */

/* VirtIO Status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE   1   /* Guest OS found device */
#define VIRTIO_STATUS_DRIVER        2   /* Guest OS knows how to drive device */
#define VIRTIO_STATUS_DRIVER_OK     4   /* Driver loaded and ready */
#define VIRTIO_STATUS_FEATURES_OK   8   /* Feature negotiation complete */
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET 64 /* Device experienced error */
#define VIRTIO_STATUS_FAILED        128 /* Something went wrong */

/* VirtIO Block device configuration */
#define VIRTIO_BLK_F_SIZE_MAX       1   /* Maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX        2   /* Maximum segments */
#define VIRTIO_BLK_F_GEOMETRY       4   /* Legacy geometry */
#define VIRTIO_BLK_F_RO             5   /* Read-only */
#define VIRTIO_BLK_F_BLK_SIZE       6   /* Block size */
#define VIRTIO_BLK_F_FLUSH          9   /* Cache flush */
#define VIRTIO_BLK_F_TOPOLOGY       10  /* Topology */

/* VirtIO Block commands */
#define VIRTIO_BLK_T_IN             0   /* Read */
#define VIRTIO_BLK_T_OUT            1   /* Write */
#define VIRTIO_BLK_T_FLUSH          4   /* Flush */

/* VirtIO Block status */
#define VIRTIO_BLK_S_OK             0   /* Success */
#define VIRTIO_BLK_S_IOERR          1   /* I/O error */
#define VIRTIO_BLK_S_UNSUPP         2   /* Unsupported */


/* Flags / structures vring (virtio) */
#define VRING_DESC_F_NEXT  1
#define VRING_DESC_F_WRITE 2
#define VRING_DESC_F_INDIRECT 4

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[]; /* taille = qsize */
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[]; /* taille = qsize */
} __attribute__((packed));

/* virtio-blk request header */
struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed));

/* S’assurer que la struct a la taille attendue (16 bytes) */
_Static_assert(sizeof(struct vring_desc) == 16, "vring_desc size must be 16");

#define VIRTIO_BLK_T_IN  0 /* read  (device -> driver) */
#define VIRTIO_BLK_T_OUT 1 /* write (driver -> device) */

typedef enum { VIO_OK = 0, VIO_ERR = -1 } vio_ret_t;

/* Externs / globals (adapte selon ton code) */


/* On étend ton vq_legacy_t pour tracking simpliste */
typedef struct {
    /* adresses physiques (guest physical) — 32 bits sur ARM 32 */
    uint32_t pa_base;    /* base phys du vq (aligné queue_align) */
    uint32_t pa_desc;
    uint32_t pa_avail;
    uint32_t pa_used;

    /* pointeurs virtuels utilisés par le kernel (uintptr_t pour être explicite) */
    uintptr_t va_base;
    uintptr_t va_desc;
    uintptr_t va_avail;
    uintptr_t va_used;

    /* tailles */
    uint32_t desc_size;
    uint32_t avail_size;
    uint32_t used_size;

    uint16_t qsize;
    uint16_t last_used_idx;
} vq_legacy_t;


extern volatile uint32_t *virtio_mmio_base; /* pointer to mmio (set lors init) */
extern uint32_t ata_sector_size; /* initialisé à l'init du blk */


// Offsets EN OCTETS
// Offsets EN OCTETS — VirtIO-MMIO legacy (Version == 1)
#define VIRTIO_MMIO_MAGIC            0x000
#define VIRTIO_MMIO_VERSION          0x004   // == 1 en legacy
#define VIRTIO_MMIO_DEVICE_ID        0x008
#define VIRTIO_MMIO_VENDOR_ID        0x00C

#define VIRTIO_MMIO_DEVICE_FEATURES  0x010   // 32-bit, PAS de *_FEATURES_SEL en legacy
#define VIRTIO_MMIO_DRIVER_FEATURES  0x020   // 32-bit, PAS de *_FEATURES_SEL en legacy

#define VIRTIO_MMIO_QUEUE_SEL        0x030
#define VIRTIO_MMIO_QUEUE_NUM_MAX    0x034
#define VIRTIO_MMIO_QUEUE_NUM        0x038
#define VIRTIO_MMIO_QUEUE_ALIGN_OFF  0x03C   // registre "QueueAlign" (offset)
#define VIRTIO_MMIO_QUEUE_PFN        0x040   // PFN (page frame number) — legacy uniquement

// PAS de QUEUE_READY en legacy (c’est QUEUE_PFN!=0 qui “arme” la queue)
#define VIRTIO_MMIO_QUEUE_NOTIFY     0x050

#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060
#define VIRTIO_MMIO_INTERRUPT_ACK    0x064

#define VIRTIO_MMIO_STATUS           0x070
#define VIRTIO_MMIO_CONFIG           0x100   // début de la config spécifique au device

#define VQ_ALIGN     4096u   // Queue alignment typique en legacy
#define VQ_SIZE      128u    // Nombre d’entrées (<= QueueNumMax)
#define VIRTIO_MMIO_QUEUE_ALIGN 4096

#define VIRTIO_MMIO_QUEUE_DESC_LOW  0x040
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x044
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW 0x048
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH 0x04C
#define VIRTIO_MMIO_QUEUE_USED_LOW  0x050
#define VIRTIO_MMIO_QUEUE_USED_HIGH 0x054
#define VIRTIO_STATUS_ACK           0x01
//#define VIRTIO_STATUS_DRIVER        0x02
//#define VIRTIO_STATUS_FEATURES_OK   0x08
//#define VIRTIO_STATUS_DRIVER_OK     0x04
//#define VIRTIO_STATUS_FAILED        0x80

/* Offsets dans virtio_blk_config pour MMIO */
#define VBLK_CFG_CAPACITY_LO   (VIRTIO_MMIO_CONFIG + 0x00) // low 32
#define VBLK_CFG_CAPACITY_HI   (VIRTIO_MMIO_CONFIG + 0x04) // high 32
#define VBLK_CFG_SIZE_MAX      (VIRTIO_MMIO_CONFIG + 0x08) // u32
#define VBLK_CFG_SEG_MAX       (VIRTIO_MMIO_CONFIG + 0x0C) // u32
#define VBLK_CFG_GEOM_C        (VIRTIO_MMIO_CONFIG + 0x10) // u16
#define VBLK_CFG_GEOM_H        (VIRTIO_MMIO_CONFIG + 0x12) // u8
#define VBLK_CFG_GEOM_S        (VIRTIO_MMIO_CONFIG + 0x13) // u8
#define VBLK_CFG_BLK_SIZE      (VIRTIO_MMIO_CONFIG + 0x1C) // u32 (si F_BLK_SIZE)

/* Fonctions publiques */
bool init_virtio_block(void);
bool virtio_block_read_sector(uint32_t lba, uint8_t* buffer);
bool virtio_block_write_sector(uint32_t lba, const uint8_t* buffer);
void virtio_block_irq_handler(void);
void virtio_block_comprehensive_test(void);
bool virtio_blk_init_legacy(uint32_t base_addr);
void read_sector0_and_print(void);

/* Fonctions utilitaires */
uint32_t virtio_read_reg(uint32_t reg);
void virtio_write_reg(uint32_t reg, uint32_t value);
//bool virtio_probe_device(void);


static inline void mmio_write32(volatile uint32_t *base, uint32_t off, uint32_t val){
    // Évite que des écritures mémoire précédentes passent après l’accès MMIO
    asm volatile("dmb ish" ::: "memory");

    *(volatile uint32_t *)((uintptr_t)base + off) = val;

    // S’assure que l’écriture est poussée vers le périphérique
    // et ne sera pas retardée avant des opérations suivantes (interruptions, etc.)
    asm volatile("dsb ishst" ::: "memory");
}


static inline uint32_t mmio_read32(volatile uint32_t *base, uint32_t off){

    volatile uint32_t *p = (volatile uint32_t *)((uintptr_t)base + off);
    uint32_t v = *p;
    asm volatile("dmb ish" ::: "memory");
    return v;
}

#endif /* _KERNEL_VIRTIO_BLOCK_H */
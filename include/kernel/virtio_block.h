/* kernel/include/kernel/virtio_block.h - VirtIO Block Device pour machine virt */
#ifndef _KERNEL_VIRTIO_BLOCK_H
#define _KERNEL_VIRTIO_BLOCK_H

#include <kernel/types.h>
#include <kernel/kernel.h>

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

/* Structure pour une requete VirtIO Block */
struct virtio_blk_req {
    uint32_t type;          /* Type de requete */
    uint32_t reserved;      /* Reserve */
    uint64_t sector;        /* Secteur LBA */
    uint8_t data[512];      /* Donnees (pour simplifier: 1 secteur) */
    uint8_t status;         /* Status de retour */
} __attribute__((packed));

/* Configuration du device VirtIO Block */
struct virtio_blk_config {
    uint64_t capacity;      /* Capacite en secteurs de 512 bytes */
    uint32_t size_max;      /* Taille max segment */
    uint32_t seg_max;       /* Nombre max segments */
    struct {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
    } geometry;             /* Geometrie legacy */
    uint32_t blk_size;      /* Taille de bloc */
} __attribute__((packed));

/* Fonctions publiques */
bool init_virtio_block(void);
bool virtio_block_read_sector(uint32_t lba, uint8_t* buffer);
bool virtio_block_write_sector(uint32_t lba, const uint8_t* buffer);
void virtio_block_irq_handler(void);
void virtio_block_comprehensive_test(void);

/* Fonctions utilitaires */
uint32_t virtio_read_reg(uint32_t reg);
void virtio_write_reg(uint32_t reg, uint32_t value);
bool virtio_probe_device(void);

#endif /* _KERNEL_VIRTIO_BLOCK_H */
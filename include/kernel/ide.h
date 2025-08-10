#ifndef _KERNEL_IDE_H
#define _KERNEL_IDE_H

#include <kernel/types.h>
#include <kernel/kernel.h>

/* Adresses IDE sur machine QEMU virt avec PCIe */
/* Ces adresses dependent de la configuration PCI */
#define IDE_PRIMARY_BASE    0x3F000000    /* Base PCI I/O pour machine virt */
#define IDE_PRIMARY_CTRL    0x3F00000E    /* Control base */
#define IDE_PRIMARY_IRQ     14            /* IRQ typique pour IDE primary */

/* Alternative: utiliser les constantes du kernel.h */
#define IDE_PCIE_BASE       VIRT_PCIE_PIO_BASE  /* 0x3EFF0000 */
#define IDE_LEGACY_IO_BASE  (IDE_PCIE_BASE + 0x1F0)  /* Port I/O legacy */

/* Registres IDE (offsets depuis base) */
#define IDE_REG_DATA        0x00    /* Data register */
#define IDE_REG_ERROR       0x01    /* Error register (read) */
#define IDE_REG_FEATURES    0x01    /* Features register (write) */
#define IDE_REG_SECCOUNT    0x02    /* Sector count */
#define IDE_REG_LBA_LOW     0x03    /* LBA bits 0-7 */
#define IDE_REG_LBA_MID     0x04    /* LBA bits 8-15 */
#define IDE_REG_LBA_HIGH    0x05    /* LBA bits 16-23 */
#define IDE_REG_DRIVE       0x06    /* Drive/Head register */
#define IDE_REG_STATUS      0x07    /* Status register (read) */
#define IDE_REG_COMMAND     0x07    /* Command register (write) */

/* Registres de controle (offset depuis ctrl_base) */
#define IDE_REG_CTRL        0x00    /* Control register */
#define IDE_REG_ALTSTATUS   0x00    /* Alternate status */

/* Commandes IDE */
#define IDE_CMD_READ_SECTORS    0x20
#define IDE_CMD_WRITE_SECTORS   0x30
#define IDE_CMD_IDENTIFY        0xEC

/* Bits du registre STATUS */
#define IDE_STATUS_BSY      0x80    /* Busy */
#define IDE_STATUS_DRDY     0x40    /* Drive ready */
#define IDE_STATUS_DF       0x20    /* Drive fault */
#define IDE_STATUS_DSC      0x10    /* Drive seek complete */
#define IDE_STATUS_DRQ      0x08    /* Data request */
#define IDE_STATUS_CORR     0x04    /* Correctable error */
#define IDE_STATUS_IDX      0x02    /* Index */
#define IDE_STATUS_ERR      0x01    /* Error */

/* Bits du registre DRIVE */
#define IDE_DRIVE_MASTER    0xA0    /* Master drive */
#define IDE_DRIVE_SLAVE     0xB0    /* Slave drive */
#define IDE_DRIVE_LBA       0x40    /* Use LBA addressing */

/* Detection automatique du type de stockage */
typedef enum {
    STORAGE_TYPE_NONE,
    STORAGE_TYPE_IDE,
    STORAGE_TYPE_VIRTIO_BLOCK,
    STORAGE_TYPE_AHCI
} storage_type_t;

/* Fonctions publiques */
void ide_irq_handler(void);
bool init_ide(void);
void ide_comprehensive_test(void);

/* Nouvelles fonctions pour detection automatique */
storage_type_t detect_storage_type(void);
bool init_storage(void);  /* Initialise le bon type de stockage */
bool storage_read_sector(uint32_t lba, uint8_t* buffer);
bool storage_write_sector(uint32_t lba, const uint8_t* buffer);

/* Test generique de stockage */
void storage_comprehensive_test(void);

#endif
#ifndef _KERNEL_ATA_H
#define _KERNEL_ATA_H

#include <kernel/types.h>

/*
 * Historical block-device compatibility API.
 *
 * The implementation now delegates to the VirtIO block driver.  Keep these
 * names while older FAT32/debug code still calls ata_* entry points.
 */

bool init_ata(void);
int ata_read_sectors(uint64_t lba, uint32_t count, void* buffer);
int ata_write_sectors(uint64_t lba, uint32_t count, const void* buffer);
void ata_irq_handler(void);
bool ata_is_initialized(void);
uint64_t ata_get_capacity_sectors(void);
uint32_t ata_get_sector_size(void);
bool ata_is_ready(void);

void ata_set_real_mode(bool enable_real);
void ata_test_both_modes(void);
void ata_simple_test(void);
void virtio_diagnose_device_state(void);
void virtio_comprehensive_test(void);
bool virtio_reconfigure_device(void);

#endif /* _KERNEL_ATA_H */

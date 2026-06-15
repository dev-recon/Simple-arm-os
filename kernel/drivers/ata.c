#include <kernel/ata.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/virtio_block.h>

/*
 * Compatibility layer.
 *
 * The real block driver lives in virtio_block.c.  This file keeps the older
 * ata_* API used by FAT32 and early boot code, without carrying a second
 * VirtIO queue implementation or simulation backend.
 */

static bool ata_initialized = false;

bool init_ata(void)
{
    KINFO("Initializing VirtIO block device...\n");

    ata_initialized = false;

    if (!virtio_blk_init_legacy((uint32_t)virtio_mmio_base)) {
        KERROR("KO VirtIO block initialization failed\n");
        return false;
    }

    ata_initialized = blk_is_initialized();
    if (!ata_initialized) {
        KERROR("KO VirtIO block driver did not become ready\n");
        return false;
    }

    KINFO("OK VirtIO block device initialized successfully!\n");
    KINFO("ATA compatibility layer: using VirtIO block driver\n");
    return true;
}

int ata_read_sectors(uint64_t lba, uint32_t count, void* buffer)
{
    if (!ata_is_initialized())
        return -1;
    return blk_read_sectors(lba, count, buffer);
}

int ata_write_sectors(uint64_t lba, uint32_t count, const void* buffer)
{
    if (!ata_is_initialized())
        return -1;
    return blk_write_sectors(lba, count, (void*)buffer);
}

void ata_irq_handler(void)
{
    virtio_block_irq_handler();
}

bool ata_is_initialized(void)
{
    return ata_initialized && blk_is_initialized();
}

uint64_t ata_get_capacity_sectors(void)
{
    return blk_get_capacity_sectors();
}

uint32_t ata_get_sector_size(void)
{
    return blk_get_sector_size();
}

bool ata_is_ready(void)
{
    return ata_is_initialized();
}

void ata_set_real_mode(bool enable_real)
{
    if (!enable_real)
        KWARN("ATA simulation mode was removed; VirtIO block remains active\n");
}

void ata_test_both_modes(void)
{
    ata_simple_test();
}

void ata_simple_test(void)
{
    static uint8_t buffer[512] __attribute__((aligned(64)));

    KINFO("=== ATA compatibility test ===\n");
    if (!ata_is_initialized()) {
        KERROR("ATA compatibility layer is not initialized\n");
        return;
    }

    memset(buffer, 0, sizeof(buffer));
    int result = ata_read_sectors(0, 1, buffer);
    KINFO("Read sector 0 result: %d\n", result);
    KINFO("Capacity: %u sectors (%u MB), sector_size=%u, readonly=%s\n",
          (uint32_t)ata_get_capacity_sectors(),
          (uint32_t)(ata_get_capacity_sectors() / 2048),
          ata_get_sector_size(),
          blk_is_readonly() ? "yes" : "no");
}

void virtio_diagnose_device_state(void)
{
    KINFO("=== VIRTIO BLOCK DEVICE DIAGNOSIS ===\n");
    KINFO("Initialized: %s\n", ata_is_initialized() ? "yes" : "no");
    KINFO("Capacity: %u sectors (%u MB)\n",
          (uint32_t)blk_get_capacity_sectors(),
          (uint32_t)(blk_get_capacity_sectors() / 2048));
    KINFO("Sector size: %u\n", blk_get_sector_size());
    KINFO("Read-only: %s\n", blk_is_readonly() ? "yes" : "no");
}

void virtio_comprehensive_test(void)
{
    virtio_diagnose_device_state();
    ata_simple_test();
}

bool virtio_reconfigure_device(void)
{
    KWARN("VirtIO live reconfiguration is not supported\n");
    return false;
}

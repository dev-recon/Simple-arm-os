/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/platform/qemu_virt/virtio_block.c
 * Layer: ARM64 / QEMU virt block bootstrap
 *
 * Responsibilities:
 * - Negotiate a VirtIO 1.0 block device over modern VirtIO MMIO.
 * - Submit bounded polling reads through a three-descriptor split ring.
 * - Validate the QEMU disk MBR and its first ext2 superblock.
 *
 * Notes:
 * - This milestone driver is read-only, single-request and interrupt-free.
 * - Queue memory remains allocated for the later persistent block-device port.
 */

#include <asm/mmu.h>
#include <kernel/block_device.h>
#include <kernel/types.h>

#include "virtio_block.h"

#define VIRTIO_MMIO_FIRST       0x0A000000ULL
#define VIRTIO_MMIO_STRIDE      0x00000200ULL
#define VIRTIO_MMIO_SLOTS       32u

#define VIRTIO_MMIO_MAGIC       0x000u
#define VIRTIO_MMIO_VERSION     0x004u
#define VIRTIO_MMIO_DEVICE_ID   0x008u
#define VIRTIO_MMIO_DEV_FEATURE 0x010u
#define VIRTIO_MMIO_DEV_SEL     0x014u
#define VIRTIO_MMIO_DRV_FEATURE 0x020u
#define VIRTIO_MMIO_DRV_SEL     0x024u
#define VIRTIO_MMIO_GUEST_PAGE  0x028u
#define VIRTIO_MMIO_QUEUE_SEL   0x030u
#define VIRTIO_MMIO_QUEUE_MAX   0x034u
#define VIRTIO_MMIO_QUEUE_NUM   0x038u
#define VIRTIO_MMIO_QUEUE_ALIGN 0x03Cu
#define VIRTIO_MMIO_QUEUE_PFN   0x040u
#define VIRTIO_MMIO_QUEUE_READY 0x044u
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050u
#define VIRTIO_MMIO_STATUS      0x070u
#define VIRTIO_MMIO_DESC_LOW    0x080u
#define VIRTIO_MMIO_DESC_HIGH   0x084u
#define VIRTIO_MMIO_AVAIL_LOW   0x090u
#define VIRTIO_MMIO_AVAIL_HIGH  0x094u
#define VIRTIO_MMIO_USED_LOW    0x0A0u
#define VIRTIO_MMIO_USED_HIGH   0x0A4u
#define VIRTIO_MMIO_CONFIG      0x100u

#define VIRTIO_MAGIC_VALUE      0x74726976u
#define VIRTIO_VERSION_LEGACY   1u
#define VIRTIO_VERSION_MODERN   2u
#define VIRTIO_DEVICE_BLOCK     2u
#define VIRTIO_STATUS_ACK       0x01u
#define VIRTIO_STATUS_DRIVER    0x02u
#define VIRTIO_STATUS_DRIVER_OK 0x04u
#define VIRTIO_STATUS_FEATURES_OK 0x08u
#define VIRTIO_F_VERSION_1_HIGH 0x00000001u
#define VIRTIO_QUEUE_SIZE       8u
#define VIRTIO_DESC_NEXT        0x01u
#define VIRTIO_DESC_WRITE       0x02u
#define VIRTIO_BLOCK_READ       0u
#define VIRTIO_BLOCK_STATUS_OK  0u
#define VIRTIO_TIMEOUT_SECONDS  2u

#define QUEUE_AVAIL_OFFSET      0x100u
#define REQUEST_STATUS_OFFSET   0x010u
#define REQUEST_DATA_OFFSET     0x040u
#define MBR_PARTITION_OFFSET    446u
#define MBR_PARTITION_SIZE      16u
#define MBR_SIGNATURE_OFFSET    510u
#define MBR_TYPE_EXT2           0x83u
#define EXT2_SUPERBLOCK_SECTOR  2u
#define EXT2_MAGIC_OFFSET       56u
#define EXT2_MAGIC              0xEF53u

typedef struct {
    uint64_t address;
    uint32_t length;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) virtio_descriptor_t;

typedef struct {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
} __attribute__((packed)) virtio_block_request_t;

typedef struct {
    volatile uint32_t *mmio;
    paddr_t queue_physical;
    paddr_t used_physical;
    paddr_t request_physical;
    uint8_t *queue_page;
    uint8_t *used_page;
    uint8_t *request_page;
    uint16_t queue_size;
    uint16_t avail_index;
    uint16_t used_index;
    uint16_t avail_offset;
    uint32_t version;
    uint64_t capacity_sectors;
} arm64_virtio_block_state_t;

static arm64_virtio_block_state_t block_state;

static int block_device_read(block_device_t *device, uint64_t lba,
                             uint32_t count, void *buffer);

static block_device_ops_t block_device_ops;
static block_device_t block_device;

static uint32_t mmio_read32(volatile uint32_t *base, uint32_t offset)
{
    return *(volatile uint32_t *)((uintptr_t)base + offset);
}

static void mmio_write32(volatile uint32_t *base, uint32_t offset,
                         uint32_t value)
{
    *(volatile uint32_t *)((uintptr_t)base + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static uint16_t read_le16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t read_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void zero_page(uint8_t *page)
{
    size_t index;

    for (index = 0; index < PAGE_SIZE; index++)
        page[index] = 0;
}

static void cache_clean_invalidate(void *pointer, size_t length)
{
    uintptr_t cursor = (uintptr_t)pointer & ~(uintptr_t)63u;
    uintptr_t end = ((uintptr_t)pointer + length + 63u) & ~(uintptr_t)63u;

    for (; cursor < end; cursor += 64u)
        __asm__ volatile("dc civac, %0" :: "r"(cursor) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

static void cache_invalidate(void *pointer, size_t length)
{
    uintptr_t cursor = (uintptr_t)pointer & ~(uintptr_t)63u;
    uintptr_t end = ((uintptr_t)pointer + length + 63u) & ~(uintptr_t)63u;

    for (; cursor < end; cursor += 64u)
        __asm__ volatile("dc ivac, %0" :: "r"(cursor) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

static volatile uint32_t *find_block_mmio(void)
{
    unsigned int slot;

    for (slot = 0; slot < VIRTIO_MMIO_SLOTS; slot++) {
        paddr_t physical = VIRTIO_MMIO_FIRST +
                           (paddr_t)slot * VIRTIO_MMIO_STRIDE;
        volatile uint32_t *base = (volatile uint32_t *)(uintptr_t)
            arm64_mmu_kernel_address(physical);

        uint32_t version = mmio_read32(base, VIRTIO_MMIO_VERSION);

        if (mmio_read32(base, VIRTIO_MMIO_MAGIC) == VIRTIO_MAGIC_VALUE &&
            (version == VIRTIO_VERSION_LEGACY ||
             version == VIRTIO_VERSION_MODERN) &&
            mmio_read32(base, VIRTIO_MMIO_DEVICE_ID) ==
                VIRTIO_DEVICE_BLOCK) {
            block_state.version = version;
            return base;
        }
    }
    return NULL;
}

static int allocate_transport(early_page_allocator_t *allocator)
{
    paddr_t pages;

    if (early_page_alloc_pages(allocator, 3, &pages) != 0)
        return -1;
    block_state.queue_physical = pages;
    block_state.used_physical = pages + PAGE_SIZE;
    block_state.request_physical = pages + 2u * PAGE_SIZE;
    block_state.queue_page = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(block_state.queue_physical);
    block_state.used_page = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(block_state.used_physical);
    block_state.request_page = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(block_state.request_physical);
    zero_page(block_state.queue_page);
    zero_page(block_state.used_page);
    zero_page(block_state.request_page);
    return 0;
}

static int negotiate_transport(void)
{
    volatile uint32_t *base = block_state.mmio;
    uint32_t status;
    uint32_t queue_max;
    uint32_t capacity_low;
    uint32_t capacity_high;

    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);
    mmio_write32(base, VIRTIO_MMIO_STATUS,
                 VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
    if (block_state.version == VIRTIO_VERSION_MODERN) {
        mmio_write32(base, VIRTIO_MMIO_DEV_SEL, 1);
        if ((mmio_read32(base, VIRTIO_MMIO_DEV_FEATURE) &
             VIRTIO_F_VERSION_1_HIGH) == 0)
            return -1;
        mmio_write32(base, VIRTIO_MMIO_DRV_SEL, 0);
        mmio_write32(base, VIRTIO_MMIO_DRV_FEATURE, 0);
        mmio_write32(base, VIRTIO_MMIO_DRV_SEL, 1);
        mmio_write32(base, VIRTIO_MMIO_DRV_FEATURE,
                     VIRTIO_F_VERSION_1_HIGH);
        status = mmio_read32(base, VIRTIO_MMIO_STATUS) |
                 VIRTIO_STATUS_FEATURES_OK;
        mmio_write32(base, VIRTIO_MMIO_STATUS, status);
        if ((mmio_read32(base, VIRTIO_MMIO_STATUS) &
             VIRTIO_STATUS_FEATURES_OK) == 0)
            return -1;
    } else {
        mmio_write32(base, VIRTIO_MMIO_DRV_FEATURE, 0);
        mmio_write32(base, VIRTIO_MMIO_GUEST_PAGE, PAGE_SIZE);
    }

    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);
    if (mmio_read32(base, VIRTIO_MMIO_QUEUE_READY) != 0)
        return -1;
    queue_max = mmio_read32(base, VIRTIO_MMIO_QUEUE_MAX);
    if (queue_max < 3)
        return -1;
    block_state.queue_size = queue_max < VIRTIO_QUEUE_SIZE ?
        (uint16_t)queue_max : VIRTIO_QUEUE_SIZE;
    block_state.avail_offset =
        block_state.version == VIRTIO_VERSION_LEGACY ?
            (uint16_t)(sizeof(virtio_descriptor_t) *
                       block_state.queue_size) : QUEUE_AVAIL_OFFSET;
    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, block_state.queue_size);
    if (block_state.version == VIRTIO_VERSION_MODERN) {
        mmio_write32(base, VIRTIO_MMIO_DESC_LOW,
                     (uint32_t)block_state.queue_physical);
        mmio_write32(base, VIRTIO_MMIO_DESC_HIGH,
                     (uint32_t)(block_state.queue_physical >> 32));
        mmio_write32(base, VIRTIO_MMIO_AVAIL_LOW,
                     (uint32_t)(block_state.queue_physical +
                                block_state.avail_offset));
        mmio_write32(base, VIRTIO_MMIO_AVAIL_HIGH,
                     (uint32_t)((block_state.queue_physical +
                                 block_state.avail_offset) >> 32));
        mmio_write32(base, VIRTIO_MMIO_USED_LOW,
                     (uint32_t)block_state.used_physical);
        mmio_write32(base, VIRTIO_MMIO_USED_HIGH,
                     (uint32_t)(block_state.used_physical >> 32));
    } else {
        mmio_write32(base, VIRTIO_MMIO_QUEUE_ALIGN, PAGE_SIZE);
        mmio_write32(base, VIRTIO_MMIO_QUEUE_PFN,
                     (uint32_t)(block_state.queue_physical >> 12));
    }
    cache_clean_invalidate(block_state.queue_page, PAGE_SIZE);
    cache_clean_invalidate(block_state.used_page, PAGE_SIZE);
    cache_clean_invalidate(block_state.request_page, PAGE_SIZE);
    if (block_state.version == VIRTIO_VERSION_MODERN)
        mmio_write32(base, VIRTIO_MMIO_QUEUE_READY, 1);
    mmio_write32(base, VIRTIO_MMIO_STATUS,
                 mmio_read32(base, VIRTIO_MMIO_STATUS) |
                 VIRTIO_STATUS_DRIVER_OK);

    capacity_low = mmio_read32(base, VIRTIO_MMIO_CONFIG);
    capacity_high = mmio_read32(base, VIRTIO_MMIO_CONFIG + 4u);
    block_state.capacity_sectors =
        ((uint64_t)capacity_high << 32) | capacity_low;
    return block_state.capacity_sectors == 0 ? -1 : 0;
}

static int read_sector(uint64_t sector, uint8_t *destination)
{
    virtio_descriptor_t *descriptors =
        (virtio_descriptor_t *)(void *)block_state.queue_page;
    volatile uint16_t *avail = (volatile uint16_t *)(void *)
        (block_state.queue_page + block_state.avail_offset);
    volatile uint16_t *used = (volatile uint16_t *)(void *)
        block_state.used_page;
    virtio_block_request_t *request =
        (virtio_block_request_t *)(void *)block_state.request_page;
    volatile uint8_t *status = block_state.request_page +
                               REQUEST_STATUS_OFFSET;
    uint8_t *data = block_state.request_page + REQUEST_DATA_OFFSET;
    uint64_t start;
    uint64_t frequency;
    uint16_t expected_used;
    size_t index;

    if (!destination || sector >= block_state.capacity_sectors)
        return -1;
    request->type = VIRTIO_BLOCK_READ;
    request->reserved = 0;
    request->sector = sector;
    *status = 0xFFu;
    descriptors[0].address = block_state.request_physical;
    descriptors[0].length = sizeof(*request);
    descriptors[0].flags = VIRTIO_DESC_NEXT;
    descriptors[0].next = 1;
    descriptors[1].address = block_state.request_physical +
                             REQUEST_DATA_OFFSET;
    descriptors[1].length = 512;
    descriptors[1].flags = VIRTIO_DESC_NEXT | VIRTIO_DESC_WRITE;
    descriptors[1].next = 2;
    descriptors[2].address = block_state.request_physical +
                             REQUEST_STATUS_OFFSET;
    descriptors[2].length = 1;
    descriptors[2].flags = VIRTIO_DESC_WRITE;
    descriptors[2].next = 0;

    avail[2 + block_state.avail_index % block_state.queue_size] = 0;
    block_state.avail_index++;
    avail[1] = block_state.avail_index;
    expected_used = block_state.used_index + 1u;
    cache_clean_invalidate(block_state.queue_page, PAGE_SIZE);
    cache_clean_invalidate(block_state.used_page, PAGE_SIZE);
    cache_clean_invalidate(block_state.request_page, PAGE_SIZE);
    mmio_write32(block_state.mmio, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(start));
    for (;;) {
        uint64_t now;

        cache_invalidate(block_state.used_page, PAGE_SIZE);
        if (used[1] == expected_used)
            break;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(now));
        if (now - start >= frequency * VIRTIO_TIMEOUT_SECONDS)
            return -1;
        __asm__ volatile("yield");
    }
    block_state.used_index = expected_used;
    cache_invalidate(block_state.request_page, PAGE_SIZE);
    if (*status != VIRTIO_BLOCK_STATUS_OK)
        return -1;
    for (index = 0; index < 512; index++)
        destination[index] = data[index];
    return 0;
}

int arm64_virtio_block_probe(early_page_allocator_t *allocator,
                             arm64_virtio_block_probe_t *result)
{
    uint8_t sector[512];
    uint32_t ext2_lba = 0;
    uint32_t ext2_sectors = 0;
    unsigned int partition;

    if (!allocator || !result)
        return -1;
    block_state.mmio = find_block_mmio();
    if (!block_state.mmio || allocate_transport(allocator) != 0 ||
        negotiate_transport() != 0 || read_sector(0, sector) != 0 ||
        sector[MBR_SIGNATURE_OFFSET] != 0x55u ||
        sector[MBR_SIGNATURE_OFFSET + 1u] != 0xAAu)
        return -1;

    for (partition = 0; partition < 4; partition++) {
        const uint8_t *entry = sector + MBR_PARTITION_OFFSET +
                               partition * MBR_PARTITION_SIZE;

        if (entry[4] == MBR_TYPE_EXT2) {
            ext2_lba = read_le32(entry + 8);
            ext2_sectors = read_le32(entry + 12);
            break;
        }
    }
    if (ext2_lba == 0 || ext2_sectors == 0 ||
        read_sector((uint64_t)ext2_lba + EXT2_SUPERBLOCK_SECTOR,
                    sector) != 0 ||
        read_le16(sector + EXT2_MAGIC_OFFSET) != EXT2_MAGIC)
        return -1;
    /*
     * Populate pointer-bearing tables after entering the high kernel alias.
     * Static link-time pointers still name the temporary low boot mapping.
     */
    block_device_ops.read_sectors = block_device_read;
    block_device_ops.write_sectors = NULL;
    block_device_ops.flush = NULL;
    block_device_ops.shutdown = NULL;
    block_device.name = "virtio0";
    block_device.capacity_sectors = block_state.capacity_sectors;
    block_device.sector_size = 512;
    block_device.read_only = true;
    block_device.ops = &block_device_ops;
    block_device.driver_data = &block_state;
    if (!blk_register(&block_device))
        return -1;
    result->capacity_sectors = block_state.capacity_sectors;
    result->ext2_start_lba = ext2_lba;
    result->ext2_sector_count = ext2_sectors;
    return 0;
}

int arm64_virtio_block_read(uint64_t lba, uint32_t count, void *buffer)
{
    uint8_t *bytes = buffer;
    uint32_t sector;

    if (!buffer || count == 0 || lba >= block_state.capacity_sectors ||
        (uint64_t)count > block_state.capacity_sectors - lba)
        return -1;
    for (sector = 0; sector < count; sector++) {
        if (read_sector(lba + sector,
                        bytes + (size_t)sector * 512u) != 0)
            return -1;
    }
    return 0;
}

static int block_device_read(block_device_t *device, uint64_t lba,
                             uint32_t count, void *buffer)
{
    if (device != &block_device)
        return -1;
    return arm64_virtio_block_read(lba, count, buffer);
}

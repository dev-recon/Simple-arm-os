/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/platform/qemu_virt/virtio_block.h
 * Layer: ARM64 / QEMU virt block bootstrap
 *
 * Responsibilities:
 * - Expose the bounded VirtIO block probe used during ARM64 bring-up.
 * - Report the disk capacity and first ext2 partition discovered through MBR.
 *
 * Notes:
 * - This interface precedes the persistent generic block-device integration.
 */

#ifndef ARMOS_ARM64_QEMU_VIRTIO_BLOCK_H
#define ARMOS_ARM64_QEMU_VIRTIO_BLOCK_H

#include <kernel/early_page_allocator.h>

typedef struct {
    uint64_t capacity_sectors;
    uint32_t ext2_start_lba;
} arm64_virtio_block_probe_t;

int arm64_virtio_block_probe(early_page_allocator_t *allocator,
                             arm64_virtio_block_probe_t *result);
int arm64_virtio_block_read(uint64_t lba, uint32_t count, void *buffer);

#endif /* ARMOS_ARM64_QEMU_VIRTIO_BLOCK_H */

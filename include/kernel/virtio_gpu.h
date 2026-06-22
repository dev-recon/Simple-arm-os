/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/virtio_gpu.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_VIRTIO_GPU_H
#define _KERNEL_VIRTIO_GPU_H

#include <kernel/types.h>

bool virtio_gpu_init(void);
bool virtio_gpu_is_initialized(void);
int virtio_gpu_flush(void);
int virtio_gpu_flush_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height);
void virtio_gpu_draw_test_pattern(void);

#endif

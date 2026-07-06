/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/platform_devices.h
 * Layer: Kernel / platform boundary
 *
 * Responsibilities:
 * - Expose board-specific device bring-up to the generic boot path.
 * - Keep kernel/main.c from knowing concrete QEMU, Raspberry Pi, or VirtIO
 *   probing details.
 *
 * Notes:
 * - tty0/UART is initialized earlier and must remain the recovery console.
 */

#ifndef _KERNEL_PLATFORM_DEVICES_H
#define _KERNEL_PLATFORM_DEVICES_H

#include <kernel/types.h>

typedef struct {
    bool tty1_graphics_ready;
} platform_devices_state_t;

platform_devices_state_t platform_devices_init(void);

#endif /* _KERNEL_PLATFORM_DEVICES_H */

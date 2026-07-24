/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/raspberrypi_mailbox.h
 * Layer: Kernel / Raspberry Pi firmware interface
 *
 * Responsibilities:
 * - Serialize property-channel requests to the Raspberry Pi firmware.
 * - Perform the cache maintenance required around VideoCore mailbox buffers.
 *
 * Notes:
 * - Property buffers must be 16-byte aligned and addressable below 4 GiB.
 */

#ifndef _KERNEL_RASPBERRYPI_MAILBOX_H
#define _KERNEL_RASPBERRYPI_MAILBOX_H

#include <kernel/types.h>

#define RPI_MBOX_RESPONSE_OK 0x80000000u

bool raspberrypi_property_call(volatile uint32_t *buffer, size_t size);
bool raspberrypi_set_power_state(uint32_t device_id, uint32_t state);
bool raspberrypi_set_firmware_gpio(uint32_t gpio, bool high);

#endif /* _KERNEL_RASPBERRYPI_MAILBOX_H */

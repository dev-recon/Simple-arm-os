/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/device_service.h
 * Layer: Kernel / device lifecycle
 *
 * Responsibilities:
 * - Register hardware-independent late device initialization callbacks.
 * - Start devices that require mounted filesystems or kernel services.
 *
 * Notes:
 * - Platform code probes transports; common drivers register their own late
 *   lifecycle work instead of adding board-specific policy to kernel/main.c.
 */

#ifndef KERNEL_DEVICE_SERVICE_H
#define KERNEL_DEVICE_SERVICE_H

#include <kernel/types.h>

typedef int (*device_service_start_t)(void);

int device_service_register(const char *name, device_service_start_t start);
void device_services_start(void);

#endif /* KERNEL_DEVICE_SERVICE_H */

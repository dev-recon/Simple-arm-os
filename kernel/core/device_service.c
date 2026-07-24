/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/core/device_service.c
 * Layer: Kernel / device lifecycle
 *
 * Responsibilities:
 * - Keep a small registry of common drivers that need late initialization.
 * - Start registered services after the root filesystem and task core exist.
 *
 * Notes:
 * - Registration occurs during the serialized boot probe, before SMP task
 *   scheduling starts, so the registry needs no dynamic allocation.
 */

#include <kernel/device_service.h>
#include <kernel/kprintf.h>

#define DEVICE_SERVICE_MAX 8u

typedef struct device_service_entry {
    const char *name;
    device_service_start_t start;
} device_service_entry_t;

static device_service_entry_t device_services[DEVICE_SERVICE_MAX];
static uint32_t device_service_count;

int device_service_register(const char *name, device_service_start_t start)
{
    if (!name || !start)
        return -EINVAL;
    if (device_service_count >= DEVICE_SERVICE_MAX)
        return -ENOSPC;

    device_services[device_service_count].name = name;
    device_services[device_service_count].start = start;
    device_service_count++;
    return 0;
}

void device_services_start(void)
{
    for (uint32_t index = 0u; index < device_service_count; index++) {
        int ret = device_services[index].start();

        if (ret < 0)
            KBOOT_WARNF("Device: %s late initialization failed (%d)",
                        device_services[index].name, ret);
    }
}

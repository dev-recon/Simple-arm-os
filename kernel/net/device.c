/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/net/device.c
 * Layer: Kernel / network core
 *
 * Responsibilities:
 * - Register Ethernet devices discovered by platform drivers.
 * - Dispatch frame I/O through a transport-neutral contract.
 * - Keep the default interface policy out of individual hardware drivers.
 *
 * Notes:
 * - Boot-time registration is serialized before secondary schedulers start.
 */

#include <kernel/net/device.h>
#include <kernel/string.h>

#define NET_DEVICE_MAX 4u

static net_device_t *net_devices[NET_DEVICE_MAX];
static uint32_t registered_device_count;
static net_device_t *net_default_device;

int net_device_register(net_device_t *device)
{
    if (!device || !device->name || !device->ops || !device->ops->transmit)
        return -EINVAL;
    if (device->mtu == 0u)
        device->mtu = NET_DEVICE_DEFAULT_MTU;
    if (strlen(device->name) >= NET_DEVICE_NAME_MAX)
        return -ENAMETOOLONG;
    if (net_device_find(device->name))
        return -EEXIST;
    if (registered_device_count >= NET_DEVICE_MAX)
        return -ENOSPC;

    net_devices[registered_device_count++] = device;
    if (!net_default_device)
        net_default_device = device;
    return 0;
}

net_device_t *net_device_get_default(void)
{
    return net_default_device;
}

net_device_t *net_device_find(const char *name)
{
    if (!name)
        return NULL;
    for (uint32_t index = 0u; index < registered_device_count; index++) {
        if (strcmp(net_devices[index]->name, name) == 0)
            return net_devices[index];
    }
    return NULL;
}

uint32_t net_device_count(void)
{
    return registered_device_count;
}

net_device_t *net_device_get(uint32_t index)
{
    if (index >= registered_device_count)
        return NULL;
    return net_devices[index];
}

int net_device_transmit(net_device_t *device, const uint8_t *frame,
                        uint32_t length)
{
    int ret;

    if (!device || !frame || length == 0u)
        return -EINVAL;
    if (!device->ops || !device->ops->transmit)
        return -ENODEV;
    if (device->link_state != NET_LINK_UP)
        return -ENETDOWN;

    ret = device->ops->transmit(device, frame, length);
    if (ret < 0) {
        device->tx_drops++;
        return ret;
    }
    device->tx_packets++;
    device->tx_bytes += length;
    return 0;
}

void net_device_receive(net_device_t *device, const uint8_t *frame,
                        uint32_t length)
{
    if (!device || !frame || length == 0u) {
        if (device)
            device->rx_drops++;
        return;
    }

    device->rx_packets++;
    device->rx_bytes += length;
    if (device->receive)
        device->receive(device, frame, length);
    else
        device->rx_drops++;
}

void net_device_set_link(net_device_t *device, net_link_state_t state)
{
    if (device)
        device->link_state = state;
}

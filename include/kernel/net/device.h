/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/device.h
 * Layer: Kernel / network core
 *
 * Responsibilities:
 * - Define the hardware-independent Ethernet device contract.
 * - Route frame transmission and reception between drivers and the net core.
 * - Expose link, MAC and packet counters without naming a transport.
 *
 * Notes:
 * - Drivers own their DMA and bus buffers; received frames are borrowed only
 *   for the duration of the receive callback.
 */

#ifndef KERNEL_NET_DEVICE_H
#define KERNEL_NET_DEVICE_H

#include <kernel/types.h>

#define NET_DEVICE_NAME_MAX 16u
#define NET_DEVICE_MAC_SIZE 6u
#define NET_DEVICE_DEFAULT_MTU 1500u

typedef enum net_link_state {
    NET_LINK_DOWN = 0,
    NET_LINK_ASSOCIATING,
    NET_LINK_UP,
} net_link_state_t;

struct net_device;

typedef int (*net_device_transmit_t)(struct net_device *device,
                                     const uint8_t *frame,
                                     uint32_t length);
typedef void (*net_device_receive_t)(struct net_device *device,
                                     const uint8_t *frame,
                                     uint32_t length);

typedef struct net_device_ops {
    net_device_transmit_t transmit;
    int (*poll)(struct net_device *device);
    void (*shutdown)(struct net_device *device);
} net_device_ops_t;

typedef struct net_device {
    const char *name;
    uint8_t mac[NET_DEVICE_MAC_SIZE];
    uint16_t mtu;
    net_link_state_t link_state;
    const net_device_ops_t *ops;
    net_device_receive_t receive;
    void *driver_data;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_drops;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_drops;
} net_device_t;

int net_device_register(net_device_t *device);
net_device_t *net_device_get_default(void);
net_device_t *net_device_find(const char *name);
int net_device_transmit(net_device_t *device, const uint8_t *frame,
                        uint32_t length);
void net_device_receive(net_device_t *device, const uint8_t *frame,
                        uint32_t length);
void net_device_set_link(net_device_t *device, net_link_state_t state);

#endif /* KERNEL_NET_DEVICE_H */

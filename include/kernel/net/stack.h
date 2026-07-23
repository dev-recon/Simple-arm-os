/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/stack.h
 * Layer: Kernel / network core
 *
 * Responsibilities:
 * - Define the architecture-neutral IPv4 configuration owned by the kernel.
 * - Attach Ethernet devices to static or DHCP-managed interfaces.
 * - Provide common ARP, ICMP echo, routed transport and daemon services.
 *
 * Notes:
 * - Hardware drivers exchange Ethernet frames only; address policy and
 *   protocols must remain independent from VirtIO, SDIO and Raspberry Pi.
 */

#ifndef KERNEL_NET_STACK_H
#define KERNEL_NET_STACK_H

#include <kernel/net/device.h>

typedef enum net_config_method {
    NET_CONFIG_STATIC = 0,
    NET_CONFIG_DHCP,
} net_config_method_t;

typedef struct net_ipv4_config {
    uint32_t address;
    uint32_t netmask;
    uint32_t gateway;
    uint32_t dns;
    uint32_t dhcp_server;
    uint32_t lease_seconds;
    bool configured;
    bool dhcp;
} net_ipv4_config_t;

typedef struct net_ping_result {
    uint32_t address;
    uint32_t sequence;
    uint32_t elapsed_ms;
    uint8_t ttl;
    bool received;
} net_ping_result_t;

int net_stack_attach(net_device_t *device, net_config_method_t method,
                     const net_ipv4_config_t *initial);
bool net_stack_receive(net_device_t *device, const uint8_t *frame,
                       uint32_t length);
int net_stack_get_config(net_device_t *device, net_ipv4_config_t *config);
int net_stack_send_ipv4(net_device_t *device, uint32_t destination,
                        uint8_t protocol, const void *payload,
                        uint32_t payload_length);
int net_stack_ping(net_device_t *device, uint32_t address,
                   uint32_t sequence, uint32_t timeout_ms,
                   net_ping_result_t *result);
int net_stack_parse_ipv4(const char *text, uint32_t *address);
void net_stack_format_ipv4(uint32_t address, char *text, uint32_t capacity);
int net_stack_format_interfaces(char *buffer, uint32_t capacity,
                                const char *name);
int net_start_daemon(void);

#endif /* KERNEL_NET_STACK_H */

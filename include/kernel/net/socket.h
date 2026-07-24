/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/socket.h
 * Layer: Kernel / network core
 *
 * Responsibilities:
 * - Define the common IPv4 socket and transport entry points.
 * - Dispatch TCP and UDP independently from the active network device.
 * - Expose socket diagnostics to procfs without depending on VirtIO.
 *
 * Notes:
 * - Addresses passed between network layers are host integers in dotted-order
 *   form (0x0A00020F means 10.0.2.15).
 */

#ifndef KERNEL_NET_SOCKET_H
#define KERNEL_NET_SOCKET_H

#include <kernel/net/device.h>

bool net_transport_receive(net_device_t *device, uint8_t protocol,
                           uint32_t source, uint32_t destination,
                           const uint8_t *payload, uint32_t length);
void net_transport_tick(uint32_t now_ms);
int net_dns_resolve(const char *name, uint32_t *address);
void net_socket_get_tcp_diag(uint32_t *local_ip, uint16_t *local_port,
                             uint32_t *listener_state,
                             uint32_t *established,
                             uint32_t *rx_bytes);

#endif /* KERNEL_NET_SOCKET_H */

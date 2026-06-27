/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/virtio_net.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Expose the minimal VirtIO network probe/status interface.
 * - Keep network bring-up independent from the future IP/TCP stack.
 */

#ifndef _KERNEL_VIRTIO_NET_H
#define _KERNEL_VIRTIO_NET_H

#include <kernel/types.h>
#include <kernel/task.h>

bool virtio_net_init(void);
bool virtio_net_is_initialized(void);
uint32_t virtio_net_get_irq(void);
void virtio_net_irq_handler(void);
void virtio_net_get_mac(uint8_t mac[6]);
bool is_net_echo_device_path(const char* path);
file_t* create_net_echo_device_file(const char* name, int flags);
void fill_net_echo_device_stat(struct stat* st);
void virtio_net_get_stats(uint32_t *irq_count, uint32_t *last_irq_status,
                          uint32_t *status, uint32_t *phys, uint32_t *irq,
                          uint32_t *rx_packets, uint32_t *rx_bytes,
                          uint32_t *rx_drops, uint32_t *rx_last_len,
                          uint32_t *tx_packets, uint32_t *tx_bytes,
                          uint32_t *tx_drops, uint32_t *rx_arp,
                          uint32_t *tx_arp, uint32_t *rx_ipv4,
                          uint32_t *rx_icmp, uint32_t *tx_icmp,
                          uint32_t *rx_tcp, uint32_t *tx_tcp,
                          uint32_t *tcp_echo, uint32_t *echo_enabled);
void virtio_net_get_tcp_diag(uint32_t *local_ip, uint16_t *local_port,
                             uint32_t *listener_state,
                             uint32_t *pending_accept,
                             uint32_t *accepted_state);

#endif

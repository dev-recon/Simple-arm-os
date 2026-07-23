/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/control.h
 * Layer: Kernel / network control device
 *
 * Responsibilities:
 * - Expose the common network stack through /dev/netctl.
 * - Keep userland diagnostics independent from a particular NIC driver.
 *
 * Notes:
 * - This textual control surface is intentionally small. General-purpose
 *   datagram and raw sockets remain a separate POSIX networking milestone.
 */

#ifndef KERNEL_NET_CONTROL_H
#define KERNEL_NET_CONTROL_H

#include <kernel/task.h>

#define DEV_NETCTL_RDEV ((10u << 8) | 200u)

bool is_net_control_device_path(const char *path);
file_t *create_net_control_device_file(const char *name, int flags);
void fill_net_control_device_stat(struct stat *st);

#endif /* KERNEL_NET_CONTROL_H */

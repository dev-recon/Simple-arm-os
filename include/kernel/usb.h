/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/usb.h
 * Layer: Kernel / USB host interface
 *
 * Responsibilities:
 * - Define the architecture-neutral USB device topology contract.
 * - Let host-controller drivers publish enumerated devices.
 * - Own the generic USB daemon and host-controller service contract.
 * - Expose stable snapshots to procfs and diagnostics.
 */

#ifndef _KERNEL_USB_H
#define _KERNEL_USB_H

#include <kernel/types.h>

#define USB_TOPOLOGY_MAX_DEVICES 32u
#define USB_MANUFACTURER_NAME_MAX 64u
#define USB_PRODUCT_NAME_MAX      96u
#define USB_SERIAL_NAME_MAX       64u

typedef enum usb_device_speed {
    USB_DEVICE_SPEED_HIGH = 0,
    USB_DEVICE_SPEED_FULL = 1,
    USB_DEVICE_SPEED_LOW = 2,
    USB_DEVICE_SPEED_SUPER = 3,
    USB_DEVICE_SPEED_UNKNOWN = 255
} usb_device_speed_t;

typedef struct usb_device_info {
    uint8_t bus;
    uint8_t address;
    uint8_t parent_address;
    uint8_t parent_port;
    uint8_t speed;
    uint8_t max_packet_size;
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    uint8_t configuration_count;
    uint8_t interface_count;
    uint8_t port_count;
    uint8_t keyboard_interfaces;
    uint8_t mouse_interfaces;
    uint16_t usb_version;
    uint16_t vendor_id;
    uint16_t product_id;
    uint16_t device_version;
    char manufacturer[USB_MANUFACTURER_NAME_MAX];
    char product[USB_PRODUCT_NAME_MAX];
    char serial[USB_SERIAL_NAME_MAX];
} usb_device_info_t;

typedef struct usb_host_controller_ops {
    const char *name;
    int (*probe)(void *context);
    void (*poll)(void *context);
} usb_host_controller_ops_t;

void usb_topology_reset(void);
int usb_topology_register(const usb_device_info_t *device);
void usb_topology_set_hub_ports(uint8_t bus, uint8_t address,
                                uint8_t port_count);
void usb_topology_note_hid(uint8_t bus, uint8_t address, uint8_t protocol);
size_t usb_topology_snapshot(usb_device_info_t *devices, size_t capacity);
const char *usb_speed_name(uint8_t speed);

int usb_host_controller_register(const usb_host_controller_ops_t *ops,
                                 void *context);
int usb_start_daemon(void);

#endif /* _KERNEL_USB_H */

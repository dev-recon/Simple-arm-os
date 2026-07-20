/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/usb/core.c
 * Layer: Kernel / USB core
 *
 * Responsibilities:
 * - Maintain an architecture-neutral snapshot of enumerated USB devices.
 * - Decouple host-controller drivers from procfs and userland presentation.
 * - Own the usbd task and dispatch host-controller probe and poll callbacks.
 * - Serialize topology publication against diagnostic readers.
 *
 * Notes:
 * - Device discovery is currently boot-time only, but the registry contract is
 *   ready for later hot-plug updates without changing /proc/usb or lsusb.
 */

#include <kernel/address_space.h>
#include <kernel/arch_memory.h>
#include <kernel/kprintf.h>
#include <kernel/process.h>
#include <kernel/spinlock.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/usb.h>

#define USB_HID_PROTOCOL_KEYBOARD 1u
#define USB_HID_PROTOCOL_MOUSE    2u
#define USB_HOST_CONTROLLER_MAX   4u
#define USBD_PRIORITY             8u

typedef struct usb_host_controller {
    const usb_host_controller_ops_t *ops;
    void *context;
    bool active;
} usb_host_controller_t;

static usb_device_info_t usb_devices[USB_TOPOLOGY_MAX_DEVICES];
static size_t usb_device_count;
static spinlock_t usb_topology_lock = SPINLOCK_INIT("usb_topology");
static usb_host_controller_t usb_controllers[USB_HOST_CONTROLLER_MAX];
static size_t usb_controller_count;
static task_t *usbd_task;

static int usb_find_device(uint8_t bus, uint8_t address)
{
    for (size_t i = 0; i < usb_device_count; i++) {
        if (usb_devices[i].bus == bus &&
            usb_devices[i].address == address)
            return (int)i;
    }
    return -1;
}

void usb_topology_reset(void)
{
    unsigned long flags;

    spin_lock_irqsave(&usb_topology_lock, &flags);
    memset(usb_devices, 0, sizeof(usb_devices));
    usb_device_count = 0;
    spin_unlock_irqrestore(&usb_topology_lock, flags);
}

int usb_topology_register(const usb_device_info_t *device)
{
    unsigned long flags;
    int index;

    if (!device || device->address == 0u)
        return -EINVAL;

    spin_lock_irqsave(&usb_topology_lock, &flags);
    index = usb_find_device(device->bus, device->address);
    if (index < 0) {
        if (usb_device_count >= USB_TOPOLOGY_MAX_DEVICES) {
            spin_unlock_irqrestore(&usb_topology_lock, flags);
            return -ENOSPC;
        }
        index = (int)usb_device_count++;
    }
    usb_devices[index] = *device;
    spin_unlock_irqrestore(&usb_topology_lock, flags);
    return 0;
}

void usb_topology_set_hub_ports(uint8_t bus, uint8_t address,
                                uint8_t port_count)
{
    unsigned long flags;
    int index;

    spin_lock_irqsave(&usb_topology_lock, &flags);
    index = usb_find_device(bus, address);
    if (index >= 0)
        usb_devices[index].port_count = port_count;
    spin_unlock_irqrestore(&usb_topology_lock, flags);
}

void usb_topology_note_hid(uint8_t bus, uint8_t address, uint8_t protocol)
{
    unsigned long flags;
    int index;

    spin_lock_irqsave(&usb_topology_lock, &flags);
    index = usb_find_device(bus, address);
    if (index >= 0) {
        if (protocol == USB_HID_PROTOCOL_KEYBOARD)
            usb_devices[index].keyboard_interfaces++;
        else if (protocol == USB_HID_PROTOCOL_MOUSE)
            usb_devices[index].mouse_interfaces++;
    }
    spin_unlock_irqrestore(&usb_topology_lock, flags);
}

size_t usb_topology_snapshot(usb_device_info_t *devices, size_t capacity)
{
    unsigned long flags;
    size_t count;

    if (!devices || capacity == 0u)
        return 0;

    spin_lock_irqsave(&usb_topology_lock, &flags);
    count = usb_device_count;
    if (count > capacity)
        count = capacity;
    memcpy(devices, usb_devices, count * sizeof(*devices));
    spin_unlock_irqrestore(&usb_topology_lock, flags);
    return count;
}

const char *usb_speed_name(uint8_t speed)
{
    switch (speed) {
    case USB_DEVICE_SPEED_HIGH:  return "high";
    case USB_DEVICE_SPEED_FULL:  return "full";
    case USB_DEVICE_SPEED_LOW:   return "low";
    case USB_DEVICE_SPEED_SUPER: return "super";
    default:                     return "unknown";
    }
}

int usb_host_controller_register(const usb_host_controller_ops_t *ops,
                                 void *context)
{
    if (!ops || !ops->name || !ops->probe || !ops->poll)
        return -EINVAL;

    for (size_t i = 0; i < usb_controller_count; i++) {
        if (usb_controllers[i].ops == ops &&
            usb_controllers[i].context == context)
            return 0;
    }
    if (usb_controller_count >= USB_HOST_CONTROLLER_MAX)
        return -ENOSPC;

    usb_controllers[usb_controller_count].ops = ops;
    usb_controllers[usb_controller_count].context = context;
    usb_controllers[usb_controller_count].active = false;
    usb_controller_count++;
    return 0;
}

static int usb_probe_controllers(void)
{
    size_t active_count = 0;

    usb_topology_reset();
    for (size_t i = 0; i < usb_controller_count; i++) {
        usb_host_controller_t *controller = &usb_controllers[i];
        int result = controller->ops->probe(controller->context);

        if (result == 0) {
            controller->active = true;
            active_count++;
            KBOOT_OKF("USB: %s controller ready", controller->ops->name);
        } else {
            controller->active = false;
            KBOOT_WARNF("USB: %s probe failed (%d)",
                        controller->ops->name, result);
        }
    }
    return active_count != 0u ? 0 : -ENODEV;
}

static void usbd_main(void *argument)
{
    (void)argument;

    for (;;) {
        for (size_t i = 0; i < usb_controller_count; i++) {
            usb_host_controller_t *controller = &usb_controllers[i];

            if (controller->active)
                controller->ops->poll(controller->context);
        }
        task_sleep_ms(1u);
    }
}

int usb_start_daemon(void)
{
    if (usb_controller_count == 0u)
        return 0;
    if (usbd_task)
        return 1;
    if (usb_probe_controllers() != 0)
        return -ENODEV;

    usbd_task = task_create_process("usbd", usbd_main, NULL, USBD_PRIORITY,
                                    TASK_TYPE_KERNEL);
    if (!usbd_task)
        return -ENOMEM;
    arch_task_context_mark_first_run(&usbd_task->context);
    arch_task_context_set_address_space(&usbd_task->context,
                                        arch_kernel_address_space_context(),
                                        ASID_KERNEL);
    arch_task_context_set_returns_to_user(&usbd_task->context, false);
    add_to_ready_queue(usbd_task);
    return 1;
}

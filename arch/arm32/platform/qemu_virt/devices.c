/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/platform/qemu_virt/devices.c
 * Layer: ARM32 / QEMU virt platform devices
 *
 * Responsibilities:
 * - Probe and attach QEMU virt devices that are not part of the core CPU/MMU
 *   bring-up.
 * - Keep VirtIO GPU/input/net details out of kernel/main.c.
 * - Preserve tty0/UART as the always-available recovery console.
 *
 * Notes:
 * - This is intentionally concrete.  The Raspberry Pi 2 port should add its
 *   own implementation rather than growing #ifdefs here.
 */

#include <kernel/display.h>
#include <kernel/kprintf.h>
#include <kernel/keyboard.h>
#include <kernel/platform_devices.h>
#include <kernel/tty.h>
#include <kernel/virtio_gpu.h>
#include <kernel/virtio_input.h>
#include <kernel/virtio_net.h>

platform_devices_state_t platform_devices_init(void)
{
    platform_devices_state_t state = {0};

    init_keyboard();

    init_display();
    if (virtio_gpu_init()) {
        KBOOT_OKF("GPU: virtio-gpu %ux%ux%u", FB_WIDTH, FB_HEIGHT, FB_BPP);
        if (framebuffer_attach_tty_backend(TTY_GRAPHICS_ID) == 0) {
            state.tty1_graphics_ready = true;
            tty_set_active(TTY_GRAPHICS_ID);
            KBOOT_OKF("TTY: console tty1 on virtio-gpu");
            if (virtio_input_init(TTY_GRAPHICS_ID)) {
                KBOOT_OKF("Input: virtio-keyboard on tty1");
            } else {
                KBOOT_WARN("Input: virtio-keyboard unavailable");
            }
        } else {
            KBOOT_WARN("TTY: tty1 framebuffer backend unavailable");
        }
    } else {
        KBOOT_WARN("GPU: virtio-gpu unavailable");
    }

    KBOOT_OKF("TTY: console tty0 on uart0");

    if (virtio_net_init()) {
        uint8_t mac[6];
        virtio_net_get_mac(mac);
        KBOOT_OKF("Net: virtio-net %02X:%02X:%02X:%02X:%02X:%02X irq %u",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                  virtio_net_get_irq());
    } else {
        KBOOT_WARN("Net: virtio-net unavailable");
    }

    return state;
}

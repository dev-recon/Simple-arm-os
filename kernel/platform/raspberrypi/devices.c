/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/platform/raspberrypi/devices.c
 * Layer: Kernel / Raspberry Pi platform devices
 *
 * Responsibilities:
 * - Publish the devices shared by supported BCM2836/BCM2837 boards.
 * - Avoid probing qemu-virt-only devices on Raspberry Pi hardware.
 */

#include <kernel/block_device.h>
#include <kernel/arch_platform.h>
#include <kernel/disk_layout.h>
#include <kernel/display.h>
#include <kernel/ili9341.h>
#include <kernel/kprintf.h>
#include <kernel/mmc/bcm2835_emmc.h>
#include <kernel/platform_devices.h>
#include <kernel/tty.h>

platform_devices_state_t platform_devices_init(void)
{
    platform_devices_state_t state = {0};

    KBOOT_OK("TTY: console tty0 on raspberry-pi PL011 uart0");
#if defined(ARMOS_PLATFORM_RASPI3) && defined(ARMOS_ENABLE_ILI9341)
    if (ili9341_init() &&
        init_display(ILI9341_WIDTH, ILI9341_HEIGHT, FB_BPP)) {
        display_set_backend(ili9341_display_backend());
        display_flush_all();
        KBOOT_OKF("GPU: ILI9341 GPIO parallel %ux%ux%u",
                  ILI9341_WIDTH, ILI9341_HEIGHT, FB_BPP);
        if (framebuffer_attach_tty_backend(TTY_GRAPHICS_ID) == 0) {
            state.tty1_graphics_ready = true;
            KBOOT_OK("TTY: console tty1 on ILI9341 /dev/fb0");
        } else {
            KBOOT_WARN("TTY: tty1 framebuffer backend unavailable");
        }
    } else {
        KBOOT_WARN("GPU: ILI9341 GPIO display unavailable");
    }
    KBOOT_WARN("Input: GPIO display is output-only");
#elif defined(ARMOS_PLATFORM_RASPI3)
    KBOOT_WARN("GPU: ILI9341 GPIO display disabled");
    KBOOT_WARN("Input: unavailable on Raspberry Pi 3 milestone 1");
#else
    KBOOT_WARNF("GPU: unavailable on %s milestone 1", arch_platform_name());
    KBOOT_WARNF("Input: unavailable on %s milestone 1", arch_platform_name());
#endif
    KBOOT_WARNF("Net: unavailable on %s milestone 1", arch_platform_name());

    return state;
}

bool platform_block_init(void)
{
    if (!bcm2835_emmc_init()) {
        KBOOT_WARN("Block: SD card unavailable");
        return false;
    }

    if (!disk_layout_init_from_mbr()) {
        KBOOT_WARN("Block: SD card present, MBR unavailable");
        return false;
    }

    KBOOT_OKF("Block: %s %uMB on SD",
              blk_get_name(),
              (uint32_t)((blk_get_capacity_sectors() * blk_get_sector_size()) /
                         (1024ULL * 1024ULL)));
    return true;
}

void platform_block_shutdown(void)
{
    bcm2835_emmc_shutdown();
}

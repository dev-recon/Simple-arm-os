/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/platform/raspi2/devices.c
 * Layer: ARM32 / Raspberry Pi 2 platform devices
 *
 * Responsibilities:
 * - Keep the first Raspberry Pi 2 milestone UART-only.
 * - Avoid probing qemu-virt-only devices on a BCM2836-style machine.
 */

#include <kernel/block_device.h>
#include <kernel/disk_layout.h>
#include <kernel/kprintf.h>
#include <kernel/mmc/bcm2835_emmc.h>
#include <kernel/platform_devices.h>

platform_devices_state_t platform_devices_init(void)
{
    platform_devices_state_t state = {0};

    KBOOT_OK("TTY: console tty0 on raspberry-pi PL011 uart0");
    KBOOT_WARN("GPU: unavailable on raspi2 milestone 1");
    KBOOT_WARN("Input: unavailable on raspi2 milestone 1");
    KBOOT_WARN("Net: unavailable on raspi2 milestone 1");

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

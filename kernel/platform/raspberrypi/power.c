/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/platform/raspberrypi/power.c
 * Layer: Kernel / Raspberry Pi power control
 *
 * Responsibilities:
 * - Quiesce Raspberry Pi hardware when the generic shutdown path reaches the
 *   final platform hook.
 *
 * Notes:
 * - Raspberry Pi 2/3 boards do not provide a generic SoC "remove 5V" poweroff.
 *   A clean OS shutdown means storage is synced/stopped, firmware-owned device
 *   power domains are turned off where available, and the ARM core is halted.
 */

#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/arch_power.h>
#include <kernel/raspberrypi_mailbox.h>
#include <kernel/uart.h>

#define BCM283X_POWER_SD_CARD           0u
#define BCM283X_POWER_USB_HCD           3u
#define BCM283X_POWER_STATE_OFF_WAIT    0x00000002u

void arch_system_off(void)
{
    bool sd_ok;
    bool usb_ok;

    arch_disable_interrupts();

    uart_puts(arch_platform_name());
    uart_puts(": firmware powerdown start\n");
    sd_ok = raspberrypi_set_power_state(BCM283X_POWER_SD_CARD,
                                        BCM283X_POWER_STATE_OFF_WAIT);
    usb_ok = raspberrypi_set_power_state(BCM283X_POWER_USB_HCD,
                                         BCM283X_POWER_STATE_OFF_WAIT);

    if (!sd_ok)
        uart_puts("raspberrypi: SD powerdown request failed\n");
    if (!usb_ok)
        uart_puts("raspberrypi: USB powerdown request failed\n");
    uart_puts("raspberrypi: halted; safe to remove power\n");

    for (;;) {
        arch_wait_for_interrupt();
    }
}

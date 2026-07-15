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

#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/arch_power.h>
#include <kernel/uart.h>

#define BCM283X_MBOX_OFFSET             0x0000B880u
#define BCM283X_MBOX_READ               0x00u
#define BCM283X_MBOX_STATUS             0x18u
#define BCM283X_MBOX_WRITE              0x20u
#define BCM283X_MBOX_FULL               0x80000000u
#define BCM283X_MBOX_EMPTY              0x40000000u
#define BCM283X_MBOX_CH_PROP            8u
#define BCM283X_MBOX_REQUEST            0u
#define BCM283X_MBOX_RESPONSE_OK        0x80000000u
#define BCM283X_MBOX_TAG_REQUEST        0u
#define BCM283X_MBOX_TAG_SET_POWER      0x00028001u
#define BCM283X_POWER_SD_CARD           0u
#define BCM283X_POWER_USB_HCD           3u
#define BCM283X_POWER_STATE_OFF_WAIT    0x00000002u
#define BCM283X_POWER_STATE_NO_DEVICE   0x00000002u

static volatile uint32_t raspberrypi_power_mbox[16]
    __attribute__((aligned(64)));

static volatile uint32_t *raspberrypi_mbox_regs(void)
{
    if (arch_mmu_enabled())
        return (volatile uint32_t *)(uintptr_t)
            (arch_platform_kernel_mmio_irqctrl2_base() +
             BCM283X_MBOX_OFFSET);
    return (volatile uint32_t *)(uintptr_t)
        (arch_platform_irqctrl2_phys_section_base() + BCM283X_MBOX_OFFSET);
}

static bool raspberrypi_mbox_call(uint8_t channel)
{
    volatile uint32_t *mbox = raspberrypi_mbox_regs();
    uint32_t request = ((uint32_t)(uintptr_t)raspberrypi_power_mbox & ~0xFu) |
                       (channel & 0xFu);
    uint32_t timeout;

    arch_clean_dcache_by_mva((const void *)raspberrypi_power_mbox,
                             sizeof(raspberrypi_power_mbox));

    timeout = 1000000u;
    while ((mbox[BCM283X_MBOX_STATUS / 4u] & BCM283X_MBOX_FULL) && --timeout)
        ;
    if (timeout == 0)
        return false;

    mbox[BCM283X_MBOX_WRITE / 4u] = request;

    timeout = 1000000u;
    while (timeout-- > 0) {
        uint32_t response;

        while ((mbox[BCM283X_MBOX_STATUS / 4u] & BCM283X_MBOX_EMPTY) && --timeout)
            ;
        if (timeout == 0)
            return false;

        response = mbox[BCM283X_MBOX_READ / 4u];
        if (response == request) {
            arch_invalidate_dcache_by_mva(
                (const void *)raspberrypi_power_mbox,
                sizeof(raspberrypi_power_mbox));
            return raspberrypi_power_mbox[1] ==
                BCM283X_MBOX_RESPONSE_OK;
        }
    }

    return false;
}

static bool raspberrypi_set_power_state(uint32_t device_id, uint32_t state)
{
    for (unsigned i = 0; i < 16; i++)
        raspberrypi_power_mbox[i] = 0;

    raspberrypi_power_mbox[0] = sizeof(raspberrypi_power_mbox);
    raspberrypi_power_mbox[1] = BCM283X_MBOX_REQUEST;
    raspberrypi_power_mbox[2] = BCM283X_MBOX_TAG_SET_POWER;
    raspberrypi_power_mbox[3] = 8;
    raspberrypi_power_mbox[4] = BCM283X_MBOX_TAG_REQUEST;
    raspberrypi_power_mbox[5] = device_id;
    raspberrypi_power_mbox[6] = state;
    raspberrypi_power_mbox[7] = 0;

    if (!raspberrypi_mbox_call(BCM283X_MBOX_CH_PROP))
        return false;
    if (raspberrypi_power_mbox[5] != device_id)
        return false;
    if (raspberrypi_power_mbox[6] & BCM283X_POWER_STATE_NO_DEVICE)
        return true;

    return (raspberrypi_power_mbox[6] & 1u) == (state & 1u);
}

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

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/platform/raspi2/power.c
 * Layer: ARM32 / Raspberry Pi 2 power control
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

#include <kernel/arch_power.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/uart.h>
#include <asm/arm.h>
#include <asm/platform.h>

#define RASPI2_MBOX_BASE             0x3F00B880u
#define RASPI2_MBOX_READ             0x00u
#define RASPI2_MBOX_STATUS           0x18u
#define RASPI2_MBOX_WRITE            0x20u
#define RASPI2_MBOX_FULL             0x80000000u
#define RASPI2_MBOX_EMPTY            0x40000000u
#define RASPI2_MBOX_CH_PROP          8u
#define RASPI2_MBOX_REQUEST          0u
#define RASPI2_MBOX_RESPONSE_OK      0x80000000u
#define RASPI2_MBOX_TAG_REQUEST      0u
#define RASPI2_MBOX_TAG_SET_POWER    0x00028001u
#define RASPI2_POWER_SD_CARD         0u
#define RASPI2_POWER_USB_HCD         3u
#define RASPI2_POWER_STATE_OFF_WAIT  0x00000002u
#define RASPI2_POWER_STATE_NO_DEVICE 0x00000002u

#define RASPI2_MBOX_KERNEL_BASE \
    (RASPI2_KERNEL_MMIO_IRQCTRL2_BASE + (RASPI2_MBOX_BASE - RASPI2_IRQCTRL_SECTION_BASE))

static volatile uint32_t raspi2_power_mbox[16] __attribute__((aligned(64)));

static volatile uint32_t *raspi2_mbox_regs(void)
{
    if (arch_mmu_enabled())
        return (volatile uint32_t *)(uintptr_t)RASPI2_MBOX_KERNEL_BASE;
    return (volatile uint32_t *)(uintptr_t)RASPI2_MBOX_BASE;
}

static bool raspi2_mbox_call(uint8_t channel)
{
    volatile uint32_t *mbox = raspi2_mbox_regs();
    uint32_t request = ((uint32_t)(uintptr_t)raspi2_power_mbox & ~0xFu) |
                       (channel & 0xFu);
    uint32_t timeout;

    clean_dcache_by_mva((const void *)raspi2_power_mbox,
                        sizeof(raspi2_power_mbox));

    timeout = 1000000u;
    while ((mbox[RASPI2_MBOX_STATUS / 4u] & RASPI2_MBOX_FULL) && --timeout)
        ;
    if (timeout == 0)
        return false;

    mbox[RASPI2_MBOX_WRITE / 4u] = request;

    timeout = 1000000u;
    while (timeout-- > 0) {
        uint32_t response;

        while ((mbox[RASPI2_MBOX_STATUS / 4u] & RASPI2_MBOX_EMPTY) && --timeout)
            ;
        if (timeout == 0)
            return false;

        response = mbox[RASPI2_MBOX_READ / 4u];
        if (response == request) {
            invalidate_dcache_by_mva((const void *)raspi2_power_mbox,
                                     sizeof(raspi2_power_mbox));
            return raspi2_power_mbox[1] == RASPI2_MBOX_RESPONSE_OK;
        }
    }

    return false;
}

static bool raspi2_set_power_state(uint32_t device_id, uint32_t state)
{
    for (unsigned i = 0; i < 16; i++)
        raspi2_power_mbox[i] = 0;

    raspi2_power_mbox[0] = sizeof(raspi2_power_mbox);
    raspi2_power_mbox[1] = RASPI2_MBOX_REQUEST;
    raspi2_power_mbox[2] = RASPI2_MBOX_TAG_SET_POWER;
    raspi2_power_mbox[3] = 8;
    raspi2_power_mbox[4] = RASPI2_MBOX_TAG_REQUEST;
    raspi2_power_mbox[5] = device_id;
    raspi2_power_mbox[6] = state;
    raspi2_power_mbox[7] = 0;

    if (!raspi2_mbox_call(RASPI2_MBOX_CH_PROP))
        return false;
    if (raspi2_power_mbox[5] != device_id)
        return false;
    if (raspi2_power_mbox[6] & RASPI2_POWER_STATE_NO_DEVICE)
        return true;

    return (raspi2_power_mbox[6] & 1u) == (state & 1u);
}

void arch_system_off(void)
{
    bool sd_ok;
    bool usb_ok;

    (void)arm_disable_irq_fiq_save();

    uart_puts(arch_platform_name());
    uart_puts(": firmware powerdown start\n");
    sd_ok = raspi2_set_power_state(RASPI2_POWER_SD_CARD,
                                   RASPI2_POWER_STATE_OFF_WAIT);
    usb_ok = raspi2_set_power_state(RASPI2_POWER_USB_HCD,
                                    RASPI2_POWER_STATE_OFF_WAIT);

    if (!sd_ok)
        uart_puts("raspberrypi: SD powerdown request failed\n");
    if (!usb_ok)
        uart_puts("raspberrypi: USB powerdown request failed\n");
    uart_puts("raspberrypi: halted; safe to remove power\n");

    for (;;) {
        wait_for_interrupt();
    }
}

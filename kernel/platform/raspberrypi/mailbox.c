/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/platform/raspberrypi/mailbox.c
 * Layer: Kernel / Raspberry Pi firmware interface
 *
 * Responsibilities:
 * - Exchange property-channel messages with the VideoCore firmware.
 * - Provide shared framebuffer and power-domain property operations.
 *
 * Notes:
 * - One lock protects the single hardware mailbox receive FIFO from consumers
 *   stealing each other's replies on SMP systems.
 */

#include <kernel/address_space.h>
#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_memory.h>
#include <kernel/arch_platform.h>
#include <kernel/kprintf.h>
#include <kernel/raspberrypi_mailbox.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>

#define RPI_MBOX_OFFSET          0x0000b880u
#define RPI_MBOX_READ            0x00u
#define RPI_MBOX_STATUS          0x18u
#define RPI_MBOX_WRITE           0x20u
#define RPI_MBOX_FULL            0x80000000u
#define RPI_MBOX_EMPTY           0x40000000u
#define RPI_MBOX_PROPERTY_CH     8u
#define RPI_MBOX_TIMEOUT_MS      2000u
#define RPI_GPU_UNCACHED_ALIAS   0xc0000000u
#define RPI_GPU_PHYSICAL_LIMIT   0x40000000u

#define RPI_TAG_SET_POWER        0x00028001u
#define RPI_TAG_SET_GPIO_STATE   0x00038041u
#define RPI_POWER_NO_DEVICE      0x00000002u
#define RPI_TAG_RESPONSE         0x80000000u
#define RPI_TAG_LENGTH_MASK      0x7fffffffu

static spinlock_t mailbox_lock = SPINLOCK_INIT("rpi_mbox");
typedef union raspberrypi_power_message {
    volatile uint32_t words[8];
    uint8_t cache_line[64];
} __attribute__((aligned(64))) raspberrypi_power_message_t;

static raspberrypi_power_message_t power_message;
static raspberrypi_power_message_t gpio_message;
static const char *mailbox_failure = "none";

static bool mailbox_timed_out(uint64_t start)
{
    uint32_t frequency = get_timer_frequency();
    uint32_t per_ms = frequency / 1000u;
    uint32_t remainder = frequency % 1000u;
    uint64_t timeout_ticks = (uint64_t)per_ms * RPI_MBOX_TIMEOUT_MS +
        (remainder * RPI_MBOX_TIMEOUT_MS + 999u) / 1000u;

    if (timeout_ticks == 0u)
        timeout_ticks = 1u;
    return get_timer_count() - start >= timeout_ticks;
}

static volatile uint32_t *mailbox_regs(void)
{
    if (arch_mmu_enabled()) {
        return (volatile uint32_t *)(uintptr_t)
            (arch_platform_kernel_mmio_irqctrl2_base() + RPI_MBOX_OFFSET);
    }
    return (volatile uint32_t *)(uintptr_t)
        (arch_platform_irqctrl2_phys_section_base() + RPI_MBOX_OFFSET);
}

bool raspberrypi_property_call(volatile uint32_t *buffer, size_t size)
{
    volatile uint32_t *regs;
    paddr_t physical;
    uint32_t request;
    uint64_t start;
    unsigned long flags;
    bool success = false;

    mailbox_failure = "invalid buffer";
    if (!buffer || size < 12u || ((uintptr_t)buffer & 0xfu) != 0u)
        return false;

    physical = virt_to_phys((vaddr_t)(uintptr_t)buffer);
    mailbox_failure = "buffer outside VideoCore RAM window";
    if (physical >= RPI_GPU_PHYSICAL_LIMIT)
        return false;
    /*
     * The mailbox transports a VideoCore bus address, not an ARM physical
     * address.  BCM2836/BCM2837 SDRAM is visible to the firmware through the
     * uncached 0xc0000000 alias used by Circle and the Raspberry Pi firmware
     * property interface.
     */
    request = RPI_GPU_UNCACHED_ALIAS |
        ((uint32_t)physical & 0x3ffffff0u) | RPI_MBOX_PROPERTY_CH;
    regs = mailbox_regs();

    spin_lock_irqsave(&mailbox_lock, &flags);

    /* Discard stale firmware replies before reusing a property buffer. */
    while (!(regs[RPI_MBOX_STATUS / 4u] & RPI_MBOX_EMPTY))
        (void)regs[RPI_MBOX_READ / 4u];

    arch_clean_dcache_by_mva((const void *)buffer, size);
    arch_data_sync_barrier();

    mailbox_failure = "mailbox write timeout";
    start = get_timer_count();
    while (regs[RPI_MBOX_STATUS / 4u] & RPI_MBOX_FULL) {
        if (mailbox_timed_out(start))
            goto out;
        arch_cpu_relax();
    }

    regs[RPI_MBOX_WRITE / 4u] = request;
    arch_data_sync_barrier();

    mailbox_failure = "mailbox response timeout";
    start = get_timer_count();
    for (;;) {
        uint32_t response;

        while (regs[RPI_MBOX_STATUS / 4u] & RPI_MBOX_EMPTY) {
            if (mailbox_timed_out(start))
                goto out;
            arch_cpu_relax();
        }

        response = regs[RPI_MBOX_READ / 4u];
        if (response == request) {
            arch_invalidate_dcache_by_mva((const void *)buffer, size);
            arch_data_sync_barrier();
            mailbox_failure = "firmware rejected property request";
            success = buffer[1] == RPI_MBOX_RESPONSE_OK;
            if (success)
                mailbox_failure = "none";
            break;
        }
    }

out:
    spin_unlock_irqrestore(&mailbox_lock, flags);
    return success;
}

bool raspberrypi_set_power_state(uint32_t device_id, uint32_t state)
{
    for (uint32_t i = 0; i < 8u; i++)
        power_message.words[i] = 0;

    power_message.words[0] = sizeof(power_message.words);
    power_message.words[1] = 0;
    power_message.words[2] = RPI_TAG_SET_POWER;
    power_message.words[3] = 8;
    power_message.words[4] = 0;
    power_message.words[5] = device_id;
    power_message.words[6] = state;
    power_message.words[7] = 0;

    if (!raspberrypi_property_call(power_message.words,
                                   sizeof(power_message.words))) {
        KWARN("Raspberry Pi mailbox: SET_POWER_STATE id=%u call failed "
              "reason=%s code=0x%08X tag=0x%08X state=0x%08X\n",
              device_id, mailbox_failure, power_message.words[1],
              power_message.words[4], power_message.words[6]);
        return false;
    }
    if (!(power_message.words[4] & RPI_TAG_RESPONSE) ||
        (power_message.words[4] & RPI_TAG_LENGTH_MASK) < 8u) {
        KWARN("Raspberry Pi mailbox: SET_POWER_STATE id=%u invalid tag "
              "response=0x%08X state=0x%08X\n",
              device_id, power_message.words[4], power_message.words[6]);
        return false;
    }
    if (power_message.words[5] != device_id) {
        KWARN("Raspberry Pi mailbox: SET_POWER_STATE id mismatch "
              "request=%u response=%u\n",
              device_id, power_message.words[5]);
        return false;
    }
    if (power_message.words[6] & RPI_POWER_NO_DEVICE) {
        KWARN("Raspberry Pi mailbox: SET_POWER_STATE id=%u unavailable "
              "state=0x%08X\n", device_id, power_message.words[6]);
        return false;
    }
    if ((power_message.words[6] & 1u) != (state & 1u)) {
        KWARN("Raspberry Pi mailbox: SET_POWER_STATE id=%u rejected "
              "request=0x%08X response=0x%08X\n",
              device_id, state, power_message.words[6]);
        return false;
    }
    return true;
}

bool raspberrypi_set_firmware_gpio(uint32_t gpio, bool high)
{
    for (uint32_t i = 0; i < 8u; i++)
        gpio_message.words[i] = 0;

    gpio_message.words[0] = sizeof(gpio_message.words);
    gpio_message.words[1] = 0;
    gpio_message.words[2] = RPI_TAG_SET_GPIO_STATE;
    gpio_message.words[3] = 8;
    gpio_message.words[4] = 0;
    gpio_message.words[5] = gpio;
    gpio_message.words[6] = high ? 1u : 0u;
    gpio_message.words[7] = 0;

    if (!raspberrypi_property_call(gpio_message.words,
                                   sizeof(gpio_message.words))) {
        KWARN("Raspberry Pi mailbox: SET_GPIO_STATE gpio=%u failed "
              "reason=%s code=0x%08X tag=0x%08X\n",
              gpio, mailbox_failure, gpio_message.words[1],
              gpio_message.words[4]);
        return false;
    }
    /*
     * Expander GPIO replies report success by replacing the requested GPIO
     * number with zero.  Unlike regular property tags, this firmware tag does
     * not reliably set the per-tag response bit; the overall mailbox response
     * was already validated by raspberrypi_property_call().
     */
    if (gpio_message.words[5] != 0u) {
        KWARN("Raspberry Pi mailbox: SET_GPIO_STATE gpio=%u rejected "
              "response tag=0x%08X status=0x%08X state=0x%08X\n",
              gpio, gpio_message.words[4], gpio_message.words[5],
              gpio_message.words[6]);
        return false;
    }
    return true;
}

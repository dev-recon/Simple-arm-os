/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/gpio/bcm283x_gpio.c
 * Layer: Kernel / GPIO controllers
 *
 * Responsibilities:
 * - Program the BCM2835/BCM2836/BCM2837 GPIO controller.
 * - Provide bank-oriented writes for parallel peripheral transports.
 *
 * Notes:
 * - The first implementation intentionally supports bank 0 only (GPIO 0-31),
 *   which covers every pin exposed by the Raspberry Pi 3 display profile.
 */

#include <kernel/arch_platform.h>
#include <kernel/gpio.h>
#include <kernel/spinlock.h>
#include <kernel/types.h>

#define BCM_GPIO_GPFSEL0 0x00u
#define BCM_GPIO_GPSET0  0x1cu
#define BCM_GPIO_GPCLR0  0x28u

#define BCM_GPIO_FUNC_INPUT  0u
#define BCM_GPIO_FUNC_OUTPUT 1u

static volatile uint32_t *gpio_base;
static spinlock_t gpio_config_lock = SPINLOCK_INIT("bcm_gpio_config");

static inline uint32_t gpio_read(uint32_t offset)
{
    return *(volatile uint32_t *)((uintptr_t)gpio_base + offset);
}

static inline void gpio_write_reg(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)((uintptr_t)gpio_base + offset) = value;
}

bool bcm283x_gpio_init(void)
{
    vaddr_t base = arch_platform_gpio_kernel_base();

    if (!base)
        return false;

    gpio_base = (volatile uint32_t *)(uintptr_t)base;
    return true;
}

void gpio_write_bank0(uint32_t set_mask, uint32_t clear_mask)
{
    if (!gpio_base)
        return;

    if (clear_mask)
        gpio_write_reg(BCM_GPIO_GPCLR0, clear_mask);
    if (set_mask)
        gpio_write_reg(BCM_GPIO_GPSET0, set_mask);
}

void gpio_write(uint32_t pin, bool high)
{
    if (pin >= 32u)
        return;

    gpio_write_bank0(high ? (1u << pin) : 0u,
                     high ? 0u : (1u << pin));
}

int gpio_configure_output(uint32_t pin, bool initial_high)
{
    uint32_t register_offset;
    uint32_t shift;
    uint32_t value;
    unsigned long flags;

    if (!gpio_base || pin >= 32u)
        return -EINVAL;

    /* Set the output latch before enabling the driver to avoid a pulse. */
    gpio_write(pin, initial_high);

    register_offset = BCM_GPIO_GPFSEL0 + (pin / 10u) * sizeof(uint32_t);
    shift = (pin % 10u) * 3u;

    spin_lock_irqsave(&gpio_config_lock, &flags);
    value = gpio_read(register_offset);
    value &= ~(7u << shift);
    value |= BCM_GPIO_FUNC_OUTPUT << shift;
    gpio_write_reg(register_offset, value);
    spin_unlock_irqrestore(&gpio_config_lock, flags);
    return 0;
}

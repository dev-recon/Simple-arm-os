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
 * - Configure the alternate functions and pulls needed by on-board buses.
 * - Provide bank-oriented writes for parallel peripheral transports.
 *
 * Notes:
 * - Fast parallel writes remain bank-0-only, while configuration supports all
 *   54 GPIOs, including the internal SD and Wi-Fi pin groups.
 */

#include <kernel/arch_barrier.h>
#include <kernel/arch_platform.h>
#include <kernel/gpio.h>
#include <kernel/spinlock.h>
#include <kernel/types.h>

#define BCM_GPIO_GPFSEL0 0x00u
#define BCM_GPIO_GPSET0  0x1cu
#define BCM_GPIO_GPCLR0  0x28u
#define BCM_GPIO_GPPUD   0x94u
#define BCM_GPIO_GPPUDCLK0 0x98u

#define BCM_GPIO_PIN_COUNT 54u

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

static void gpio_pull_delay(void)
{
    for (uint32_t i = 0; i < 180u; i++)
        arch_cpu_relax();
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
    if (!gpio_base || pin >= 32u)
        return -EINVAL;

    /* Set the output latch before enabling the driver to avoid a pulse. */
    gpio_write(pin, initial_high);

    return gpio_configure(pin, GPIO_FUNCTION_OUTPUT, GPIO_PULL_NONE);
}

int gpio_configure(uint32_t pin, gpio_function_t function, gpio_pull_t pull)
{
    uint32_t register_offset;
    uint32_t shift;
    uint32_t value;
    uint32_t bank;
    uint32_t mask;
    unsigned long flags;

    if (!gpio_base || pin >= BCM_GPIO_PIN_COUNT || function > GPIO_FUNCTION_ALT3 ||
        pull > GPIO_PULL_UP)
        return -EINVAL;

    register_offset = BCM_GPIO_GPFSEL0 + (pin / 10u) * sizeof(uint32_t);
    shift = (pin % 10u) * 3u;

    spin_lock_irqsave(&gpio_config_lock, &flags);
    value = gpio_read(register_offset);
    value &= ~(7u << shift);
    value |= (uint32_t)function << shift;
    gpio_write_reg(register_offset, value);

    /* BCM2837 uses the legacy GPPUD clocked pull-control sequence. */
    bank = pin / 32u;
    mask = 1u << (pin % 32u);
    gpio_write_reg(BCM_GPIO_GPPUD, (uint32_t)pull);
    gpio_pull_delay();
    gpio_write_reg(BCM_GPIO_GPPUDCLK0 + bank * sizeof(uint32_t), mask);
    gpio_pull_delay();
    gpio_write_reg(BCM_GPIO_GPPUD, 0u);
    gpio_write_reg(BCM_GPIO_GPPUDCLK0 + bank * sizeof(uint32_t), 0u);
    spin_unlock_irqrestore(&gpio_config_lock, flags);
    return 0;
}

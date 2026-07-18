/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/gpio/gpio_parallel8.c
 * Layer: Kernel / GPIO peripheral transports
 *
 * Responsibilities:
 * - Implement a write-only 8-bit 8080-style bus using GPIO bank writes.
 * - Precompute sparse GPIO masks so each data byte needs no pin loop.
 *
 * Notes:
 * - CS, WR, and reset are active low. DC is low for commands and high for
 *   data. The peripheral RD input is deliberately not driven here.
 */

#include <kernel/gpio.h>
#include <kernel/gpio_parallel8.h>
#include <kernel/string.h>

typedef struct gpio_parallel8_state {
    gpio_parallel8_config_t config;
    uint32_t data_mask;
    uint32_t data_lut[256];
    bool initialized;
} gpio_parallel8_state_t;

static gpio_parallel8_state_t bus;

static bool pin_valid(uint8_t pin)
{
    return pin < 32u;
}

bool gpio_parallel8_init(const gpio_parallel8_config_t *config)
{
    uint32_t control_mask;

    if (!config || !bcm283x_gpio_init())
        return false;

    memset(&bus, 0, sizeof(bus));
    bus.config = *config;

    if (!pin_valid(config->cs_pin) || !pin_valid(config->dc_pin) ||
        !pin_valid(config->wr_pin) || !pin_valid(config->reset_pin))
        return false;

    control_mask = (1u << config->cs_pin) | (1u << config->dc_pin) |
                   (1u << config->wr_pin) | (1u << config->reset_pin);

    for (uint32_t bit = 0; bit < 8u; bit++) {
        uint8_t pin = config->data_pins[bit];

        if (!pin_valid(pin) || (control_mask & (1u << pin)) ||
            (bus.data_mask & (1u << pin)))
            return false;
        bus.data_mask |= 1u << pin;
    }

    for (uint32_t value = 0; value < 256u; value++) {
        uint32_t mask = 0;
        for (uint32_t bit = 0; bit < 8u; bit++) {
            if (value & (1u << bit))
                mask |= 1u << config->data_pins[bit];
        }
        bus.data_lut[value] = mask;
    }

    for (uint32_t bit = 0; bit < 8u; bit++) {
        if (gpio_configure_output(config->data_pins[bit], false) < 0)
            return false;
    }

    if (gpio_configure_output(config->cs_pin, true) < 0 ||
        gpio_configure_output(config->dc_pin, true) < 0 ||
        gpio_configure_output(config->wr_pin, true) < 0 ||
        gpio_configure_output(config->reset_pin, true) < 0)
        return false;

    bus.initialized = true;
    return true;
}

void gpio_parallel8_reset(bool asserted)
{
    if (bus.initialized)
        gpio_write(bus.config.reset_pin, !asserted);
}

void gpio_parallel8_set_data_mode(bool data_mode)
{
    if (bus.initialized)
        gpio_write(bus.config.dc_pin, data_mode);
}

void gpio_parallel8_begin(bool data_mode)
{
    if (!bus.initialized)
        return;

    gpio_parallel8_set_data_mode(data_mode);
    gpio_write(bus.config.cs_pin, false);
}

void gpio_parallel8_write(uint8_t value)
{
    if (!bus.initialized)
        return;

    gpio_write_bank0(bus.data_lut[value], bus.data_mask);
    gpio_write(bus.config.wr_pin, false);
    gpio_write(bus.config.wr_pin, true);
}

void gpio_parallel8_end(void)
{
    if (bus.initialized)
        gpio_write(bus.config.cs_pin, true);
}

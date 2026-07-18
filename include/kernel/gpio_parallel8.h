/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/gpio_parallel8.h
 * Layer: Kernel / GPIO peripheral transports
 *
 * Responsibilities:
 * - Drive an 8-bit write-only 8080-style parallel bus over BCM283x GPIO.
 * - Keep LCD command/data signalling independent from a display controller.
 */

#ifndef _KERNEL_GPIO_PARALLEL8_H
#define _KERNEL_GPIO_PARALLEL8_H

#include <kernel/types.h>

typedef struct gpio_parallel8_config {
    uint8_t data_pins[8];
    uint8_t cs_pin;
    uint8_t dc_pin;
    uint8_t wr_pin;
    uint8_t reset_pin;
} gpio_parallel8_config_t;

bool gpio_parallel8_init(const gpio_parallel8_config_t *config);
void gpio_parallel8_reset(bool asserted);
void gpio_parallel8_begin(bool data_mode);
void gpio_parallel8_set_data_mode(bool data_mode);
void gpio_parallel8_write(uint8_t value);
void gpio_parallel8_end(void);

#endif /* _KERNEL_GPIO_PARALLEL8_H */

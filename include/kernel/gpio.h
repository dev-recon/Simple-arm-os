/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/gpio.h
 * Layer: Kernel / GPIO controller interface
 *
 * Responsibilities:
 * - Configure BCM283x GPIO pins as digital or alternate-function signals.
 * - Select the legacy BCM283x pull-up/pull-down state used by board buses.
 * - Update GPIO banks efficiently for parallel peripheral buses.
 */

#ifndef _KERNEL_GPIO_H
#define _KERNEL_GPIO_H

#include <kernel/types.h>

typedef enum {
    GPIO_FUNCTION_INPUT = 0,
    GPIO_FUNCTION_OUTPUT = 1,
    GPIO_FUNCTION_ALT5 = 2,
    GPIO_FUNCTION_ALT4 = 3,
    GPIO_FUNCTION_ALT0 = 4,
    GPIO_FUNCTION_ALT1 = 5,
    GPIO_FUNCTION_ALT2 = 6,
    GPIO_FUNCTION_ALT3 = 7,
} gpio_function_t;

typedef enum {
    GPIO_PULL_NONE = 0,
    GPIO_PULL_DOWN = 1,
    GPIO_PULL_UP = 2,
} gpio_pull_t;

bool bcm283x_gpio_init(void);
int gpio_configure(uint32_t pin, gpio_function_t function, gpio_pull_t pull);
int gpio_configure_output(uint32_t pin, bool initial_high);
void gpio_write(uint32_t pin, bool high);
void gpio_write_bank0(uint32_t set_mask, uint32_t clear_mask);

#endif /* _KERNEL_GPIO_H */

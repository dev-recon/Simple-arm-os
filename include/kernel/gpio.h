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
 * - Configure BCM283x GPIO pins as digital outputs.
 * - Update GPIO banks efficiently for parallel peripheral buses.
 */

#ifndef _KERNEL_GPIO_H
#define _KERNEL_GPIO_H

#include <kernel/types.h>

bool bcm283x_gpio_init(void);
int gpio_configure_output(uint32_t pin, bool initial_high);
void gpio_write(uint32_t pin, bool high);
void gpio_write_bank0(uint32_t set_mask, uint32_t clear_mask);

#endif /* _KERNEL_GPIO_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/mmc/bcm2835_sdhost.h
 * Layer: Kernel / block drivers
 *
 * Responsibilities:
 * - Declare the BCM2835 custom SDHOST block driver.
 * - Allow Raspberry Pi 3 to keep its Arasan controller free for SDIO Wi-Fi.
 *
 * Notes:
 * - This first implementation deliberately uses polling PIO and single-block
 *   transfers. Correct controller ownership comes before throughput tuning.
 */

#ifndef _KERNEL_BCM2835_SDHOST_H
#define _KERNEL_BCM2835_SDHOST_H

#include <kernel/types.h>

bool bcm2835_sdhost_init(void);
void bcm2835_sdhost_shutdown(void);

#endif /* _KERNEL_BCM2835_SDHOST_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/mmc/bcm2835_emmc.h
 * Layer: Kernel / block drivers
 *
 * Responsibilities:
 * - Declare the BCM2835/BCM2836 EMMC SD-card block driver.
 * - Keep Raspberry Pi 2 platform code from knowing controller internals.
 *
 * Notes:
 * - The first driver milestone is polling PIO, single-block I/O.  DMA and IRQ
 *   completion can be added once QEMU and real-board behavior are both known.
 */

#ifndef _KERNEL_BCM2835_EMMC_H
#define _KERNEL_BCM2835_EMMC_H

#include <kernel/types.h>

bool bcm2835_emmc_init(void);
void bcm2835_emmc_shutdown(void);

#endif /* _KERNEL_BCM2835_EMMC_H */

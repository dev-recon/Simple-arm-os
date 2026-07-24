/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/mmc/bcm2835_sdio.h
 * Layer: Kernel / SDIO host controllers
 *
 * Responsibilities:
 * - Expose the Raspberry Pi Arasan SDIO host used by the on-board radio.
 * - Provide CMD52 and CMD53 transfers to SDIO function drivers.
 * - Report the discovered SDIO identity without embedding Wi-Fi policy.
 *
 * Notes:
 * - The boot SD card must use SDHOST before this controller is claimed.
 */

#ifndef _KERNEL_MMC_BCM2835_SDIO_H
#define _KERNEL_MMC_BCM2835_SDIO_H

#include <kernel/types.h>

typedef struct bcm2835_sdio_identity {
    uint16_t manufacturer;
    uint16_t product;
    uint16_t rca;
    uint8_t functions;
    uint8_t cccr_revision;
    uint8_t sdio_revision;
} bcm2835_sdio_identity_t;

bool bcm2835_sdio_init(bcm2835_sdio_identity_t *identity);
bool bcm2835_sdio_is_ready(void);
void bcm2835_sdio_shutdown(void);

int bcm2835_sdio_readb(uint8_t function, uint32_t address, uint8_t *value);
int bcm2835_sdio_writeb(uint8_t function, uint32_t address, uint8_t value);
int bcm2835_sdio_read(uint8_t function, uint32_t address, void *buffer,
                      uint32_t length, bool increment_address);
int bcm2835_sdio_write(uint8_t function, uint32_t address,
                       const void *buffer, uint32_t length,
                       bool increment_address);

#endif /* _KERNEL_MMC_BCM2835_SDIO_H */

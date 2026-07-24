/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/cyw43.h
 * Layer: Kernel / network device drivers
 *
 * Responsibilities:
 * - Describe the Broadcom/Cypress CYW43 SDIO device discovered by ArmOS.
 * - Expose the transport-independent chip probe to Raspberry Pi platforms.
 * - Report control-plane readiness and the firmware-provided MAC address.
 *
 * Notes:
 * - Firmware loading and the BCDC data path are deliberately separate stages.
 */

#ifndef KERNEL_NET_CYW43_H
#define KERNEL_NET_CYW43_H

#include <kernel/types.h>

typedef struct cyw43_identity {
    uint32_t chip_id_register;
    uint32_t erom_address;
    uint32_t chipcommon;
    uint32_t arm_core;
    uint32_t arm_registers;
    uint32_t arm_wrapper;
    uint32_t sdio_registers;
    uint32_t d11_wrapper;
    uint32_t ram_base;
    uint32_t ram_size;
    uint16_t chip_id;
    uint8_t chip_revision;
    uint8_t package;
} cyw43_identity_t;

bool cyw43_probe(cyw43_identity_t *identity);
bool cyw43_is_present(void);
bool cyw43_is_radio_ready(void);
int cyw43_get_mac_address(uint8_t address[6]);
int cyw43_start(void);
void cyw43_shutdown(void);

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/raspberrypi_hdmi.h
 * Layer: Kernel / display controllers
 *
 * Responsibilities:
 * - Request an HDMI-backed framebuffer from Raspberry Pi firmware.
 * - Publish its geometry and display backend to the common framebuffer layer.
 */

#ifndef _KERNEL_RASPBERRYPI_HDMI_H
#define _KERNEL_RASPBERRYPI_HDMI_H

#include <kernel/display_backend.h>

typedef struct raspberrypi_hdmi_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t size;
    uint32_t virtual_height;
    paddr_t physical;
    uint8_t *virtual_address;
} raspberrypi_hdmi_info_t;

bool raspberrypi_hdmi_init(uint32_t width, uint32_t height);
const raspberrypi_hdmi_info_t *raspberrypi_hdmi_get_info(void);
const display_backend_ops_t *raspberrypi_hdmi_display_backend(void);

#endif /* _KERNEL_RASPBERRYPI_HDMI_H */

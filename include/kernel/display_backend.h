/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/display_backend.h
 * Layer: Kernel / display backend contract
 *
 * Responsibilities:
 * - Decouple the common framebuffer console from a concrete display device.
 * - Let VirtIO and physical LCD controllers expose the same /dev/fb0 ABI.
 *
 * Notes:
 * - The in-memory framebuffer remains ARGB8888. Backends may convert pixels
 *   while flushing to their native format.
 */

#ifndef _KERNEL_DISPLAY_BACKEND_H
#define _KERNEL_DISPLAY_BACKEND_H

#include <kernel/types.h>

#define ARMOS_FB_ORIENTATION_PORTRAIT  0u
#define ARMOS_FB_ORIENTATION_LANDSCAPE 1u

typedef struct display_backend_ops {
    const char *name;
    int (*flush_rect)(const uint8_t *framebuffer, uint32_t pitch,
                      uint32_t x, uint32_t y,
                      uint32_t width, uint32_t height);
    bool (*check_resize)(void);
    int (*set_orientation)(uint32_t orientation,
                           uint32_t *width, uint32_t *height);
} display_backend_ops_t;

#endif /* _KERNEL_DISPLAY_BACKEND_H */

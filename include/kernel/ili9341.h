/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/ili9341.h
 * Layer: Kernel / display controllers
 *
 * Responsibilities:
 * - Initialize an ILI9341-compatible 240x320 TFT controller.
 * - Publish its display backend for a primary or auxiliary framebuffer.
 * - Attach an output-only text terminal to its independent framebuffer.
 */

#ifndef _KERNEL_ILI9341_H
#define _KERNEL_ILI9341_H

#include <kernel/display_backend.h>

#define ILI9341_WIDTH  240u
#define ILI9341_HEIGHT 320u

bool ili9341_init(void);
const display_backend_ops_t *ili9341_display_backend(void);
int ili9341_attach_auxiliary_tty(int tty_id);

#endif /* _KERNEL_ILI9341_H */

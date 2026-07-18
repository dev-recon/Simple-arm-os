/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/video/ili9341.c
 * Layer: Kernel / display controllers
 *
 * Responsibilities:
 * - Initialize the ILI9341-compatible controller on the HSD028309 B6 panel.
 * - Flush common ARGB8888 dirty rectangles as native RGB565 pixels.
 *
 * Notes:
 * - The first milestone is deliberately write-only. LCD_RD must be held high.
 * - Window endpoints are inclusive: 0..239 and 0..319 for the full panel.
 */

#include <kernel/arch_platform.h>
#include <kernel/gpio_parallel8.h>
#include <kernel/ili9341.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>

#define ILI9341_SWRESET 0x01u
#define ILI9341_SLPOUT  0x11u
#define ILI9341_DISPON  0x29u
#define ILI9341_CASET   0x2au
#define ILI9341_PASET   0x2bu
#define ILI9341_RAMWR   0x2cu
#define ILI9341_MADCTL  0x36u
#define ILI9341_PIXFMT  0x3au

static bool ili9341_ready;
static uint32_t ili9341_width = ILI9341_WIDTH;
static uint32_t ili9341_height = ILI9341_HEIGHT;
static uint32_t ili9341_orientation = ARMOS_FB_ORIENTATION_PORTRAIT;
static spinlock_t ili9341_lock = SPINLOCK_INIT("ili9341");

static void ili9341_delay_ms(uint32_t milliseconds)
{
    uint64_t start = get_timer_count();
    uint32_t ticks_per_ms = get_timer_frequency() / 1000u;
    uint64_t duration;

    if (!ticks_per_ms)
        ticks_per_ms = 1u;
    duration = (uint64_t)ticks_per_ms * milliseconds;

    while ((get_timer_count() - start) < duration)
        __asm__ volatile("nop");
}

static void ili9341_write_command(uint8_t command,
                                  const uint8_t *data, uint32_t length)
{
    gpio_parallel8_begin(false);
    gpio_parallel8_write(command);
    if (length) {
        gpio_parallel8_set_data_mode(true);
        for (uint32_t i = 0; i < length; i++)
            gpio_parallel8_write(data[i]);
    }
    gpio_parallel8_end();
}

static void ili9341_set_window(uint32_t x, uint32_t y,
                               uint32_t width, uint32_t height)
{
    uint32_t x_end = x + width - 1u;
    uint32_t y_end = y + height - 1u;
    uint8_t column[] = {
        (uint8_t)(x >> 8), (uint8_t)x,
        (uint8_t)(x_end >> 8), (uint8_t)x_end,
    };
    uint8_t page[] = {
        (uint8_t)(y >> 8), (uint8_t)y,
        (uint8_t)(y_end >> 8), (uint8_t)y_end,
    };

    ili9341_write_command(ILI9341_CASET, column, sizeof(column));
    ili9341_write_command(ILI9341_PASET, page, sizeof(page));
}

static int ili9341_flush_rect(const uint8_t *framebuffer, uint32_t pitch,
                              uint32_t x, uint32_t y,
                              uint32_t width, uint32_t height)
{
    if (!ili9341_ready || !framebuffer || !pitch)
        return -ENODEV;

    spin_lock(&ili9341_lock);
    if (!width || !height || x >= ili9341_width || y >= ili9341_height) {
        spin_unlock(&ili9341_lock);
        return 0;
    }
    if (x + width > ili9341_width)
        width = ili9341_width - x;
    if (y + height > ili9341_height)
        height = ili9341_height - y;

    ili9341_set_window(x, y, width, height);
    gpio_parallel8_begin(false);
    gpio_parallel8_write(ILI9341_RAMWR);
    gpio_parallel8_set_data_mode(true);

    for (uint32_t row = 0; row < height; row++) {
        const uint32_t *pixels = (const uint32_t *)(const void *)
            (framebuffer + (y + row) * pitch + x * sizeof(uint32_t));

        for (uint32_t column = 0; column < width; column++) {
            uint32_t argb = pixels[column];
            uint16_t rgb565 = (uint16_t)((((argb >> 16) & 0xffu) >> 3) << 11) |
                              (uint16_t)((((argb >> 8) & 0xffu) >> 2) << 5) |
                              (uint16_t)((argb & 0xffu) >> 3);
            gpio_parallel8_write((uint8_t)(rgb565 >> 8));
            gpio_parallel8_write((uint8_t)rgb565);
        }
    }

    gpio_parallel8_end();
    spin_unlock(&ili9341_lock);
    return 0;
}

static int ili9341_set_orientation(uint32_t orientation,
                                   uint32_t *width, uint32_t *height)
{
    uint8_t madctl;
    uint32_t next_width;
    uint32_t next_height;

    if (!ili9341_ready)
        return -ENODEV;
    if (!width || !height)
        return -EINVAL;

    switch (orientation) {
    case ARMOS_FB_ORIENTATION_PORTRAIT:
        madctl = 0x48u;
        next_width = ILI9341_WIDTH;
        next_height = ILI9341_HEIGHT;
        break;
    case ARMOS_FB_ORIENTATION_LANDSCAPE:
        madctl = 0x28u;
        next_width = ILI9341_HEIGHT;
        next_height = ILI9341_WIDTH;
        break;
    default:
        return -EINVAL;
    }

    spin_lock(&ili9341_lock);
    if (orientation != ili9341_orientation) {
        ili9341_write_command(ILI9341_MADCTL, &madctl, 1u);
        ili9341_orientation = orientation;
        ili9341_width = next_width;
        ili9341_height = next_height;
    }
    spin_unlock(&ili9341_lock);

    *width = next_width;
    *height = next_height;
    return 0;
}

static const display_backend_ops_t ili9341_backend = {
    .name = "ili9341-gpio-parallel8",
    .flush_rect = ili9341_flush_rect,
    .check_resize = NULL,
    .set_orientation = ili9341_set_orientation,
};

bool ili9341_init(void)
{
    const gpio_parallel8_config_t config = {
        .data_pins = {
            ARMOS_PLATFORM_ILI9341_D0_PIN,
            ARMOS_PLATFORM_ILI9341_D1_PIN,
            ARMOS_PLATFORM_ILI9341_D2_PIN,
            ARMOS_PLATFORM_ILI9341_D3_PIN,
            ARMOS_PLATFORM_ILI9341_D4_PIN,
            ARMOS_PLATFORM_ILI9341_D5_PIN,
            ARMOS_PLATFORM_ILI9341_D6_PIN,
            ARMOS_PLATFORM_ILI9341_D7_PIN,
        },
        .cs_pin = ARMOS_PLATFORM_ILI9341_CS_PIN,
        .dc_pin = ARMOS_PLATFORM_ILI9341_DC_PIN,
        .wr_pin = ARMOS_PLATFORM_ILI9341_WR_PIN,
        .reset_pin = ARMOS_PLATFORM_ILI9341_RESET_PIN,
    };
    static const uint8_t power_control_a[] = { 0x39, 0x2c, 0x00, 0x34, 0x02 };
    static const uint8_t power_control_b[] = { 0x00, 0xc1, 0x30 };
    static const uint8_t driver_timing_a[] = { 0x85, 0x00, 0x78 };
    static const uint8_t driver_timing_b[] = { 0x00, 0x00 };
    static const uint8_t power_on_sequence[] = { 0x64, 0x03, 0x12, 0x81 };
    static const uint8_t pump_ratio[] = { 0x20 };
    static const uint8_t power_control_1[] = { 0x23 };
    static const uint8_t power_control_2[] = { 0x10 };
    static const uint8_t vcom_control_1[] = { 0x3e, 0x28 };
    static const uint8_t vcom_control_2[] = { 0x86 };
    static const uint8_t madctl[] = { 0x48 };
    static const uint8_t pixel_format[] = { 0x55 };
    static const uint8_t frame_rate[] = { 0x00, 0x18 };
    static const uint8_t display_function[] = { 0x08, 0x82, 0x27 };

    ili9341_ready = false;
    ili9341_width = ILI9341_WIDTH;
    ili9341_height = ILI9341_HEIGHT;
    ili9341_orientation = ARMOS_FB_ORIENTATION_PORTRAIT;
    if (!gpio_parallel8_init(&config))
        return false;

    gpio_parallel8_reset(true);
    ili9341_delay_ms(20);
    gpio_parallel8_reset(false);
    ili9341_delay_ms(120);

    ili9341_write_command(ILI9341_SWRESET, NULL, 0);
    ili9341_delay_ms(5);
    ili9341_write_command(0xcbu, power_control_a, sizeof(power_control_a));
    ili9341_write_command(0xcfu, power_control_b, sizeof(power_control_b));
    ili9341_write_command(0xe8u, driver_timing_a, sizeof(driver_timing_a));
    ili9341_write_command(0xeau, driver_timing_b, sizeof(driver_timing_b));
    ili9341_write_command(0xedu, power_on_sequence, sizeof(power_on_sequence));
    ili9341_write_command(0xf7u, pump_ratio, sizeof(pump_ratio));
    ili9341_write_command(0xc0u, power_control_1, sizeof(power_control_1));
    ili9341_write_command(0xc1u, power_control_2, sizeof(power_control_2));
    ili9341_write_command(0xc5u, vcom_control_1, sizeof(vcom_control_1));
    ili9341_write_command(0xc7u, vcom_control_2, sizeof(vcom_control_2));
    ili9341_write_command(ILI9341_MADCTL, madctl, sizeof(madctl));
    ili9341_write_command(ILI9341_PIXFMT, pixel_format, sizeof(pixel_format));
    ili9341_write_command(0xb1u, frame_rate, sizeof(frame_rate));
    ili9341_write_command(0xb6u, display_function, sizeof(display_function));
    ili9341_write_command(ILI9341_SLPOUT, NULL, 0);
    ili9341_delay_ms(120);
    ili9341_write_command(ILI9341_DISPON, NULL, 0);
    ili9341_delay_ms(20);

    ili9341_ready = true;
    return true;
}

const display_backend_ops_t *ili9341_display_backend(void)
{
    return ili9341_ready ? &ili9341_backend : NULL;
}

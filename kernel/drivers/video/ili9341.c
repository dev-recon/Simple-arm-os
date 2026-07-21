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
#include <kernel/display.h>
#include <kernel/spinlock.h>
#include <kernel/string.h>
#include <kernel/timer.h>
#include <kernel/tty.h>

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

#define ILI9341_AUX_CAPACITY (ILI9341_WIDTH * ILI9341_HEIGHT)
#define ILI9341_ANSI_PARAMS  8u

typedef enum {
    ILI9341_ANSI_NORMAL = 0,
    ILI9341_ANSI_ESC,
    ILI9341_ANSI_CSI,
} ili9341_ansi_state_t;

typedef struct {
    bool attached;
    int tty_id;
    uint32_t cursor_x;
    uint32_t cursor_y;
    uint32_t columns;
    uint32_t rows;
    uint32_t fg;
    uint32_t bg;
    ili9341_ansi_state_t ansi_state;
    uint32_t ansi_params[ILI9341_ANSI_PARAMS];
    uint32_t ansi_count;
    bool ansi_active;
    spinlock_t lock;
} ili9341_aux_console_t;

static uint32_t ili9341_aux_pixels[ILI9341_AUX_CAPACITY]
    __attribute__((aligned(64)));
static ili9341_aux_console_t ili9341_aux = {
    .tty_id = -1,
    .lock = SPINLOCK_INIT("ili9341_aux"),
};

static const uint32_t ili9341_ansi_colors[8] = {
    0xff000000u, 0xffaa0000u, 0xff00aa00u, 0xffaa5500u,
    0xff0000aau, 0xffaa00aau, 0xff00aaaau, 0xffaaaaaau,
};

static const uint32_t ili9341_ansi_bright_colors[8] = {
    0xff555555u, 0xffff5555u, 0xff55ff55u, 0xffffff55u,
    0xff5555ffu, 0xffff55ffu, 0xff55ffffu, 0xffffffffu,
};

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

static void ili9341_aux_mark_cell(uint32_t column, uint32_t row)
{
    display_mark_auxiliary_dirty(column * font_vga_8x16.width,
                                 row * font_vga_8x16.height,
                                 font_vga_8x16.width,
                                 font_vga_8x16.height);
}

static void ili9341_aux_draw_cell(uint32_t column, uint32_t row, char ch)
{
    uint32_t x = column * font_vga_8x16.width;
    uint32_t y = row * font_vga_8x16.height;
    const uint8_t *glyph = NULL;

    if (x + font_vga_8x16.width > ili9341_width ||
        y + font_vga_8x16.height > ili9341_height)
        return;
    if ((uint8_t)ch >= font_vga_8x16.first &&
        (uint8_t)ch <= font_vga_8x16.last) {
        uint32_t glyph_index = (uint8_t)ch - font_vga_8x16.first;
        glyph = font_vga_8x16.glyphs +
            glyph_index * font_vga_8x16.width * font_vga_8x16.height;
    }

    for (uint32_t gy = 0; gy < font_vga_8x16.height; gy++) {
        uint32_t *pixels = &ili9341_aux_pixels[(y + gy) * ili9341_width + x];

        for (uint32_t gx = 0; gx < font_vga_8x16.width; gx++) {
            uint8_t alpha = glyph ?
                glyph[gy * font_vga_8x16.width + gx] : 0;
            pixels[gx] = alpha >= 128u ? ili9341_aux.fg : ili9341_aux.bg;
        }
    }
    ili9341_aux_mark_cell(column, row);
}

static void ili9341_aux_clear(void)
{
    uint32_t count = ili9341_width * ili9341_height;

    for (uint32_t i = 0; i < count; i++)
        ili9341_aux_pixels[i] = ili9341_aux.bg;
    ili9341_aux.cursor_x = 0;
    ili9341_aux.cursor_y = 0;
    display_mark_auxiliary_dirty(0, 0, ili9341_width, ili9341_height);
}

static void ili9341_aux_clear_line_from_cursor(void)
{
    uint32_t y = ili9341_aux.cursor_y * font_vga_8x16.height;
    uint32_t x = ili9341_aux.cursor_x * font_vga_8x16.width;

    if (y >= ili9341_height || x >= ili9341_width)
        return;
    for (uint32_t row = 0; row < font_vga_8x16.height; row++) {
        uint32_t *pixels = &ili9341_aux_pixels[(y + row) * ili9341_width + x];

        for (uint32_t column = x; column < ili9341_width; column++)
            pixels[column - x] = ili9341_aux.bg;
    }
    display_mark_auxiliary_dirty(x, y, ili9341_width - x,
                                 font_vga_8x16.height);
}

static void ili9341_aux_scroll(void)
{
    uint32_t line_pixels = ili9341_width * font_vga_8x16.height;
    uint32_t retained = ili9341_width *
        (ili9341_height - font_vga_8x16.height);

    memmove(ili9341_aux_pixels,
            ili9341_aux_pixels + line_pixels,
            retained * sizeof(uint32_t));
    for (uint32_t i = retained; i < retained + line_pixels; i++)
        ili9341_aux_pixels[i] = ili9341_aux.bg;
    if (ili9341_aux.rows)
        ili9341_aux.cursor_y = ili9341_aux.rows - 1u;
    display_mark_auxiliary_dirty(0, 0, ili9341_width, ili9341_height);
}

static void ili9341_aux_newline(void)
{
    ili9341_aux.cursor_x = 0;
    ili9341_aux.cursor_y++;
    if (ili9341_aux.cursor_y >= ili9341_aux.rows)
        ili9341_aux_scroll();
}

static uint32_t ili9341_aux_param(uint32_t index, uint32_t fallback)
{
    if (index >= ili9341_aux.ansi_count)
        return fallback;
    return ili9341_aux.ansi_params[index];
}

static void ili9341_aux_apply_sgr(void)
{
    if (ili9341_aux.ansi_count == 0u) {
        ili9341_aux.fg = 0xffaaaaaau;
        ili9341_aux.bg = 0xff000000u;
        return;
    }

    for (uint32_t i = 0; i < ili9341_aux.ansi_count; i++) {
        uint32_t value = ili9341_aux.ansi_params[i];

        if (value == 0u) {
            ili9341_aux.fg = 0xffaaaaaau;
            ili9341_aux.bg = 0xff000000u;
        } else if (value >= 30u && value <= 37u) {
            ili9341_aux.fg = ili9341_ansi_colors[value - 30u];
        } else if (value >= 40u && value <= 47u) {
            ili9341_aux.bg = ili9341_ansi_colors[value - 40u];
        } else if (value >= 90u && value <= 97u) {
            ili9341_aux.fg = ili9341_ansi_bright_colors[value - 90u];
        } else if (value >= 100u && value <= 107u) {
            ili9341_aux.bg = ili9341_ansi_bright_colors[value - 100u];
        }
    }
}

static void ili9341_aux_execute_csi(char command)
{
    uint32_t amount;

    switch (command) {
    case 'A':
        amount = ili9341_aux_param(0, 1u);
        ili9341_aux.cursor_y = amount > ili9341_aux.cursor_y ?
            0u : ili9341_aux.cursor_y - amount;
        break;
    case 'B':
        amount = ili9341_aux_param(0, 1u);
        ili9341_aux.cursor_y = MIN(ili9341_aux.cursor_y + amount,
                                  ili9341_aux.rows - 1u);
        break;
    case 'C':
        amount = ili9341_aux_param(0, 1u);
        ili9341_aux.cursor_x = MIN(ili9341_aux.cursor_x + amount,
                                  ili9341_aux.columns - 1u);
        break;
    case 'D':
        amount = ili9341_aux_param(0, 1u);
        ili9341_aux.cursor_x = amount > ili9341_aux.cursor_x ?
            0u : ili9341_aux.cursor_x - amount;
        break;
    case 'H':
    case 'f': {
        uint32_t row = ili9341_aux_param(0, 1u);
        uint32_t column = ili9341_aux_param(1, 1u);

        ili9341_aux.cursor_y = MIN(row ? row - 1u : 0u,
                                  ili9341_aux.rows - 1u);
        ili9341_aux.cursor_x = MIN(column ? column - 1u : 0u,
                                  ili9341_aux.columns - 1u);
        break;
    }
    case 'J':
        if (ili9341_aux_param(0, 0u) == 2u ||
            ili9341_aux_param(0, 0u) == 0u)
            ili9341_aux_clear();
        break;
    case 'K':
        ili9341_aux_clear_line_from_cursor();
        break;
    case 'm':
        ili9341_aux_apply_sgr();
        break;
    default:
        break;
    }
}

static void ili9341_aux_putchar_locked(char ch)
{
    if (ili9341_aux.ansi_state == ILI9341_ANSI_ESC) {
        ili9341_aux.ansi_state = ch == '[' ?
            ILI9341_ANSI_CSI : ILI9341_ANSI_NORMAL;
        ili9341_aux.ansi_count = 0;
        ili9341_aux.ansi_active = false;
        memset(ili9341_aux.ansi_params, 0, sizeof(ili9341_aux.ansi_params));
        return;
    }
    if (ili9341_aux.ansi_state == ILI9341_ANSI_CSI) {
        if (ch >= '0' && ch <= '9') {
            uint32_t index = MIN(ili9341_aux.ansi_count,
                                 ILI9341_ANSI_PARAMS - 1u);
            ili9341_aux.ansi_params[index] =
                ili9341_aux.ansi_params[index] * 10u + (uint32_t)(ch - '0');
            ili9341_aux.ansi_active = true;
            return;
        }
        if (ch == ';') {
            if (ili9341_aux.ansi_count < ILI9341_ANSI_PARAMS)
                ili9341_aux.ansi_count++;
            ili9341_aux.ansi_active = false;
            return;
        }
        if (ili9341_aux.ansi_active || ili9341_aux.ansi_count)
            ili9341_aux.ansi_count++;
        ili9341_aux_execute_csi(ch);
        ili9341_aux.ansi_state = ILI9341_ANSI_NORMAL;
        return;
    }

    if (ch == '\033') {
        ili9341_aux.ansi_state = ILI9341_ANSI_ESC;
    } else if (ch == '\r') {
        ili9341_aux.cursor_x = 0;
    } else if (ch == '\n') {
        ili9341_aux_newline();
    } else if (ch == '\b' || ch == 0x7f) {
        if (ili9341_aux.cursor_x)
            ili9341_aux.cursor_x--;
        ili9341_aux_draw_cell(ili9341_aux.cursor_x,
                              ili9341_aux.cursor_y, ' ');
    } else if (ch == '\t') {
        uint32_t next = (ili9341_aux.cursor_x + 8u) & ~7u;
        ili9341_aux.cursor_x = MIN(next, ili9341_aux.columns - 1u);
    } else if ((uint8_t)ch >= 0x20u) {
        ili9341_aux_draw_cell(ili9341_aux.cursor_x,
                              ili9341_aux.cursor_y, ch);
        ili9341_aux.cursor_x++;
        if (ili9341_aux.cursor_x >= ili9341_aux.columns)
            ili9341_aux_newline();
    }
}

static void ili9341_aux_tty_putc(char ch)
{
    spin_lock(&ili9341_aux.lock);
    ili9341_aux_putchar_locked(ch);
    spin_unlock(&ili9341_aux.lock);
}

static bool ili9341_aux_tty_try_putc(char ch)
{
    ili9341_aux_tty_putc(ch);
    return true;
}

static void ili9341_aux_tty_puts(const char *text)
{
    if (!text)
        return;
    spin_lock(&ili9341_aux.lock);
    while (*text)
        ili9341_aux_putchar_locked(*text++);
    spin_unlock(&ili9341_aux.lock);
}

static void ili9341_aux_tty_tx(bool enabled)
{
    (void)enabled;
}

static bool ili9341_aux_tty_has_data(void)
{
    return false;
}

static int ili9341_aux_tty_getc(void)
{
    return -1;
}

static const tty_backend_ops_t ili9341_aux_tty_backend = {
    .putc = ili9341_aux_tty_putc,
    .try_putc = ili9341_aux_tty_try_putc,
    .puts = ili9341_aux_tty_puts,
    .set_tx_irq_enabled = ili9341_aux_tty_tx,
    .has_data = ili9341_aux_tty_has_data,
    .getc = ili9341_aux_tty_getc,
};

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

    if (ili9341_aux.attached) {
        spin_lock(&ili9341_aux.lock);
        ili9341_aux.columns = next_width / font_vga_8x16.width;
        ili9341_aux.rows = next_height / font_vga_8x16.height;
        ili9341_aux.cursor_x = 0;
        ili9341_aux.cursor_y = 0;
        for (uint32_t i = 0; i < next_width * next_height; i++)
            ili9341_aux_pixels[i] = ili9341_aux.bg;
        spin_unlock(&ili9341_aux.lock);
        tty_set_winsize_for_id(ili9341_aux.tty_id,
                               (uint16_t)ili9341_aux.rows,
                               (uint16_t)ili9341_aux.columns,
                               (uint16_t)next_width,
                               (uint16_t)next_height);
    }

    *width = next_width;
    *height = next_height;
    return 0;
}

static const display_backend_ops_t ili9341_backend = {
    .name = "ili9341-gpio-parallel8",
    .flush_rect = ili9341_flush_rect,
    .check_resize = NULL,
    .set_orientation = ili9341_set_orientation,
    .set_mode = NULL,
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

int ili9341_attach_auxiliary_tty(int tty_id)
{
    auxiliary_framebuffer_config_t config;
    int ret;

    if (!ili9341_ready)
        return -ENODEV;

    spin_lock(&ili9341_aux.lock);
    ili9341_aux.attached = true;
    ili9341_aux.tty_id = tty_id;
    ili9341_aux.columns = ili9341_width / font_vga_8x16.width;
    ili9341_aux.rows = ili9341_height / font_vga_8x16.height;
    ili9341_aux.cursor_x = 0;
    ili9341_aux.cursor_y = 0;
    ili9341_aux.fg = 0xffaaaaaau;
    ili9341_aux.bg = 0xff000000u;
    ili9341_aux.ansi_state = ILI9341_ANSI_NORMAL;
    ili9341_aux.ansi_count = 0;
    ili9341_aux.ansi_active = false;
    for (uint32_t i = 0; i < ili9341_width * ili9341_height; i++)
        ili9341_aux_pixels[i] = ili9341_aux.bg;
    spin_unlock(&ili9341_aux.lock);

    memset(&config, 0, sizeof(config));
    config.name = "ili9341";
    config.framebuffer = (uint8_t *)(void *)ili9341_aux_pixels;
    config.width = ili9341_width;
    config.height = ili9341_height;
    config.pitch = ili9341_width * sizeof(uint32_t);
    config.bpp = 32u;
    config.size = sizeof(ili9341_aux_pixels);
    config.orientation = ili9341_orientation;
    config.backend = &ili9341_backend;

    ret = display_register_auxiliary_framebuffer(&config);
    if (ret < 0)
        return ret;
    ret = tty_attach_output_backend_to(tty_id, &ili9341_aux_tty_backend);
    if (ret < 0)
        return ret;

    tty_set_winsize_for_id(tty_id,
                           (uint16_t)ili9341_aux.rows,
                           (uint16_t)ili9341_aux.columns,
                           (uint16_t)ili9341_width,
                           (uint16_t)ili9341_height);
    return 0;
}

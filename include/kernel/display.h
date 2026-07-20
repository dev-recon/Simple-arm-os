/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/display.h
 * Layer: Kernel / terminal and character devices
 *
 * Responsibilities:
 * - Drive UART/framebuffer console backends and TTY line discipline.
 * - Preserve canonical/raw terminal semantics and job-control signals.
 *
 * Notes:
 * - tty0/UART must remain a reliable fallback path.
 */

#ifndef _KERNEL_DISPLAY_H
#define _KERNEL_DISPLAY_H

#include <kernel/types.h>
#include <kernel/vfs.h>  /* Pour file_t */
#include <kernel/display_backend.h>

/* Default QEMU framebuffer geometry. Physical backends select their own. */
#define FB_WIDTH        1024
#define FB_HEIGHT       768
#define FB_BPP          32
#define FB_SIZE         (FB_WIDTH * FB_HEIGHT * (FB_BPP / 8))  /* ~3MB */

/* FB_BASE sera alloue dynamiquement en RAM */
extern uint8_t* framebuffer_base;  /* CPU virtual pointer to the framebuffer */
extern paddr_t framebuffer_phys;   /* Physical/DMA address of framebuffer_base */

#define FB_BASE         ((vaddr_t)(uintptr_t)framebuffer_base)
#define DEV_FB0_RDEV   ((29u << 8) | 0u)

#define ARMOS_FBIOGET_INFO      0x4600u
#define ARMOS_FBIOGET_ORIENTATION 0x4601u
#define ARMOS_FBIOSET_ORIENTATION 0x4602u
#define ARMOS_FBIOSET_MODE      0x4603u
#define ARMOS_FB_FORMAT_ARGB8888 1u

struct armos_fb_info {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t size;
    uint32_t format;
};

struct armos_fb_orientation {
    uint32_t orientation;
};

struct armos_fb_mode {
    uint32_t width;
    uint32_t height;
};

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t first;
    uint32_t last;
    const uint8_t *glyphs; /* width * height alpha bytes per glyph */
} font_t;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint8_t* framebuffer;
    uint32_t text_cols;
    uint32_t text_rows;
    uint32_t cursor_x;
    uint32_t cursor_y;
    uint32_t fg_color;
    uint32_t bg_color;
    const font_t *font;
} display_state_t;

extern const font_t font_meslo_12x24;
extern const font_t font_meslo_10x20;
extern const font_t font_meslo_8x16;
extern const font_t font_spleen_8x16;
extern const font_t font_spleen_12x24;
extern const font_t font_vga_8x16;

/* Display functions */
bool init_display(uint32_t width, uint32_t height, uint32_t bpp);
bool init_display_external(uint32_t width, uint32_t height, uint32_t bpp,
                           uint32_t pitch, paddr_t physical,
                           uint8_t *virtual_address, uint32_t size);
void display_set_backend(const display_backend_ops_t *backend);
const char *display_backend_name(void);
void display_flush_all(void);
void clear_screen(void);
void put_pixel(uint32_t x, uint32_t y, uint32_t color);
void draw_char(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg);
void console_putchar(char c);
void console_puts(const char* str);
void scroll_screen(void);
int framebuffer_attach_tty_backend(int tty_id);
void display_cursor_tick(void);
int display_start_daemon(void);
void display_scrollback_up(uint32_t lines);
void display_scrollback_down(uint32_t lines);

/* Framebuffer file operations */
ssize_t framebuffer_read(file_t* file, void* buffer, size_t count);
ssize_t framebuffer_write(file_t* file, const void* buffer, size_t count);
bool is_framebuffer_device_path(const char* path);
void fill_framebuffer_device_stat(struct stat* st);
int framebuffer_get_info(struct armos_fb_info* info);
int framebuffer_get_orientation(struct armos_fb_orientation *orientation);
int framebuffer_set_orientation(const struct armos_fb_orientation *orientation);
int framebuffer_set_mode(const struct armos_fb_mode *mode);
file_t* create_framebuffer_device_file(const char* name, int flags);

#endif

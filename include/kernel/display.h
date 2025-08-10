#ifndef _KERNEL_DISPLAY_H
#define _KERNEL_DISPLAY_H

#include <kernel/types.h>
#include <kernel/vfs.h>  /* Pour file_t */

/* Framebuffer */
/* NOUVEAU: Framebuffer en RAM au lieu d'une adresse hardware fixe */
#define FB_WIDTH        1024
#define FB_HEIGHT       768
#define FB_BPP          32
#define FB_SIZE         (FB_WIDTH * FB_HEIGHT * (FB_BPP / 8))  /* ~3MB */

/* FB_BASE sera alloue dynamiquement en RAM */
extern uint8_t* framebuffer_base;  /* Pointeur global vers le framebuffer */

#define FB_BASE         ((uint32_t)framebuffer_base)



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
} display_state_t;

/* Display functions */
void init_display(void);
void clear_screen(void);
void put_pixel(uint32_t x, uint32_t y, uint32_t color);
void draw_char(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg);
void console_putchar(char c);
void console_puts(const char* str);
void scroll_screen(void);

/* Framebuffer file operations */
ssize_t framebuffer_read(file_t* file, void* buffer, size_t count);
ssize_t framebuffer_write(file_t* file, const void* buffer, size_t count);

#endif
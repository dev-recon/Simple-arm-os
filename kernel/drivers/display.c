#include <kernel/display.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

static display_state_t display = {0};

/* Variable globale pour le framebuffer */
uint8_t* framebuffer_base = NULL;


void init_display(void)
{
    KINFO("=== DISPLAY INITIALIZATION (RAM-based) ===\n");
    
    /* Allouer le framebuffer en RAM */
    uint32_t fb_size = FB_WIDTH * FB_HEIGHT * (FB_BPP / 8);
    KINFO("Allocating framebuffer: %u bytes (%u KB)\n", 
            fb_size, fb_size / 1024);
    
    /* Allouer des pages contigues pour le framebuffer */
    uint32_t pages_needed = (fb_size + PAGE_SIZE - 1) / PAGE_SIZE;
    KINFO("Pages needed: %u\n", pages_needed);
    
    framebuffer_base = (uint8_t*)allocate_pages(pages_needed);
    if (!framebuffer_base) {
        KERROR("Failed to allocate framebuffer memory\n");
        return;
    }
    
    KINFO("Framebuffer allocated at: 0x%08X\n", (uint32_t)framebuffer_base);
    
    /* Le framebuffer est en RAM, donc deja mappe - pas besoin de mapping MMU */
    
    display.width = FB_WIDTH;
    display.height = FB_HEIGHT;
    display.bpp = FB_BPP;
    display.pitch = FB_WIDTH * (FB_BPP / 8);
    display.framebuffer = framebuffer_base;
    display.font = &font_meslo_12x24;
    
    /* Test d'acces au framebuffer */
    KINFO("Testing framebuffer access...\n");
    volatile uint32_t* fb_test = (volatile uint32_t*)framebuffer_base;
    
    /* Test d'ecriture */
    *fb_test = 0x12345678;
    uint32_t read_back = *fb_test;
    
    if (read_back == 0x12345678) {
        KINFO("Framebuffer write/read test PASSED\n");
        
        /* Console mode */
        display.text_cols = display.width / display.font->width;
        display.text_rows = display.height / display.font->height;
        display.cursor_x = 0;
        display.cursor_y = 0;
        display.fg_color = 0xFFFFFFFF;
        display.bg_color = 0xFF000000;
        
        clear_screen();
        KINFO("Display initialized: %d x %d (RAM-based)\n", 
                display.width, display.height);
        
    } else {
        KERROR("Framebuffer write/read test FAILED\n");
        KERROR("   Written: 0x12345678, Read: 0x%08X\n", read_back);
        
        /* Liberer la memoire en cas d'echec */
        free_pages(framebuffer_base, pages_needed);
        framebuffer_base = NULL;
    }
}


void clear_screen(void)
{
    uint32_t* fb32 = (uint32_t*)display.framebuffer;
    uint32_t pixels = display.width * display.height;
    uint32_t i;
    
    for (i = 0; i < pixels; i++) {
        fb32[i] = display.bg_color;
    }
    
    display.cursor_x = 0;
    display.cursor_y = 0;
}

void put_pixel(uint32_t x, uint32_t y, uint32_t color)
{
    if (x >= display.width || y >= display.height) return;
    
    uint32_t* fb32 = (uint32_t*)display.framebuffer;
    fb32[y * display.width + x] = color;
}

static uint32_t blend_argb(uint32_t fg, uint32_t bg, uint8_t alpha)
{
    if (alpha == 0)
        return bg;
    if (alpha == 255)
        return fg;

    uint32_t inv = 255u - alpha;
    uint32_t fr = (fg >> 16) & 0xFF;
    uint32_t fg_g = (fg >> 8) & 0xFF;
    uint32_t fb = fg & 0xFF;
    uint32_t br = (bg >> 16) & 0xFF;
    uint32_t bg_g = (bg >> 8) & 0xFF;
    uint32_t bb = bg & 0xFF;
    uint32_t r = (fr * alpha + br * inv + 127) / 255;
    uint32_t g = (fg_g * alpha + bg_g * inv + 127) / 255;
    uint32_t b = (fb * alpha + bb * inv + 127) / 255;

    return 0xFF000000u | (r << 16) | (g << 8) | b;
}

void draw_char(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t bg)
{
    const font_t *font = display.font;
    if (!font || !font->glyphs)
        return;

    uint32_t code = (uint8_t)c;
    if (code < font->first || code > font->last)
        code = '?';

    const uint8_t *glyph = font->glyphs +
        (code - font->first) * font->width * font->height;

    for (uint32_t row = 0; row < font->height; row++) {
        for (uint32_t col = 0; col < font->width; col++) {
            uint8_t alpha = glyph[row * font->width + col];
            uint32_t color = blend_argb(fg, bg, alpha);
            put_pixel(x + col, y + row, color);
        }
    }
}

void console_putchar(char c)
{
    switch (c) {
        case '\n':
            display.cursor_x = 0;
            display.cursor_y++;
            break;
            
        case '\r':
            display.cursor_x = 0;
            break;
            
        case '\b':
            if (display.cursor_x > 0) {
                display.cursor_x--;
                draw_char(display.cursor_x * display.font->width,
                         display.cursor_y * display.font->height, ' ',
                         display.fg_color, display.bg_color);
            }
            break;
            
        case '\t':
            display.cursor_x = (display.cursor_x + 8) & ~7;
            break;
            
        default:
            if (c >= 32 && c <= 126) {
                draw_char(display.cursor_x * display.font->width,
                         display.cursor_y * display.font->height, c,
                         display.fg_color, display.bg_color);
                display.cursor_x++;
            }
            break;
    }
    
    if (display.cursor_x >= display.text_cols) {
        display.cursor_x = 0;
        display.cursor_y++;
    }
    
    if (display.cursor_y >= display.text_rows) {
        scroll_screen();
    }
}

void console_puts(const char* str)
{
    while (*str) {
        console_putchar(*str++);
    }
}

void scroll_screen(void)
{
    uint32_t font_h = display.font ? display.font->height : 16;
    uint32_t line_bytes = display.width * font_h * 4;
    uint32_t y;
    
    /* Copy lines up */
    for (y = 0; y < display.height - font_h; y += font_h) {
        memcpy(display.framebuffer + (y * display.pitch),
               display.framebuffer + ((y + font_h) * display.pitch),
               line_bytes);
    }
    
    /* Clear last line */
    uint32_t* last_line = (uint32_t*)(display.framebuffer + 
                                     ((display.height - font_h) * display.pitch));
    uint32_t i;
    for (i = 0; i < display.width * font_h; i++) {
        last_line[i] = display.bg_color;
    }
    
    display.cursor_y = display.text_rows - 1;
}

ssize_t framebuffer_write(file_t* file, const void* buffer, size_t count)
{
    const char* data = (const char*)buffer;
    size_t i;
    
    /* Suppression du warning unused parameter */
    (void)file;
    
    for (i = 0; i < count; i++) {
        console_putchar(data[i]);
    }
    
    return count;
}

ssize_t framebuffer_read(file_t* file, void* buffer, size_t count)
{
    /* Read raw framebuffer data */
    uint32_t offset = file->offset;
    uint32_t fb_size = display.width * display.height * 4;
    
    if (offset >= fb_size) {
        return 0;
    }
    
    uint32_t available = fb_size - offset;
    uint32_t to_copy = MIN(count, available);
    
    memcpy(buffer, display.framebuffer + offset, to_copy);
    file->offset += to_copy;
    
    return to_copy;
}

#ifndef ANSI_TTY_H
#define ANSI_TTY_H

#include <stddef.h>
#include <unistd.h>

/* Primitive d'envoi d'une chaîne */
static inline void tty_puts(const char *s) {
    while (*s) putc_tty(*s++);
}

/* Emet ESC (0x1B) */
static inline void tty_emit_esc(void) { putc_tty('\x1b'); }

/* Emet CSI avec params (param peut être NULL) et la commande finale (ex: 'H','m','J') */
static inline void tty_emit_csi(const char *param, char cmd) {
    tty_emit_esc();
    putc_tty('[');
    if (param) tty_puts(param);
    putc_tty(cmd);
}

/* Convertit un entier non signé en décimal dans buf (buf doit être suffisamment grand)
   Retourne le nombre de caractères écrits (pas de '\0'). */
static inline int append_uint(char *buf, unsigned int v) {
    if (v == 0) { buf[0] = '0'; return 1; }
    char tmp[12];
    int ti = 0;
    while (v) { tmp[ti++] = '0' + (v % 10); v /= 10; }
    for (int i = 0; i < ti; ++i) buf[i] = tmp[ti - 1 - i];
    return ti;
}

/* Fonctions utilitaires */
 
/* Cursor */
static inline void tty_cursor_home(void) { tty_emit_csi((char *)NULL, 'H'); }
/* Positionne (r,c) 1-based */
static inline void tty_cursor_pos(unsigned int r, unsigned int c) {
    char buf[32];
    int p = 0;
    p += append_uint(buf + p, r);
    buf[p++] = ';';
    p += append_uint(buf + p, c);
    buf[p] = '\0';
    tty_emit_csi(buf, 'H');
}

/* Clear */
static inline void tty_clear_screen(void) { tty_emit_csi("2", 'J'); tty_cursor_pos(1,1); }
static inline void tty_clear_line(void)   { tty_emit_csi("2", 'K'); }

/* Cursor show/hide */
static inline void tty_cursor_hide(void) { tty_emit_csi("?25", 'l'); }
static inline void tty_cursor_show(void) { tty_emit_csi("?25", 'h'); }

/* SGR (Select Graphic Rendition) : reset/bold etc. */
static inline void tty_sgr_reset(void) { tty_emit_csi("0", 'm'); }
static inline void tty_sgr_bold(void)  { tty_emit_csi("1", 'm'); }
static inline void tty_sgr_underline(void) { tty_emit_csi("4", 'm'); }

/* Basic 8-colors FG: n = 0..7 (black..white) */
static inline void tty_fg_basic(unsigned int n) {
    char buf[8];
    int p = 0;
    p += append_uint(buf + p, 30 + (n & 7));
    buf[p] = '\0';
    tty_emit_csi(buf, 'm');
}

/* Basic BG: n = 0..7 */
static inline void tty_bg_basic(unsigned int n) {
    char buf[8];
    int p = 0;
    p += append_uint(buf + p, 40 + (n & 7));
    buf[p] = '\0';
    tty_emit_csi(buf, 'm');
}

/* 256-color FG: n = 0..255 -> CSI 38;5;{n}m */
static inline void tty_fg_256(unsigned int n) {
    char buf[16];
    int p = 0;
    p += append_uint(buf + p, 38); buf[p++] = ';';
    buf[p++] = '5'; buf[p++] = ';';
    p += append_uint(buf + p, n & 0xFF);
    buf[p] = '\0';
    tty_emit_csi(buf, 'm');
}

/* 256-color BG: CSI 48;5;{n}m */
static inline void tty_bg_256(unsigned int n) {
    char buf[16];
    int p = 0;
    p += append_uint(buf + p, 48); buf[p++] = ';';
    buf[p++] = '5'; buf[p++] = ';';
    p += append_uint(buf + p, n & 0xFF);
    buf[p] = '\0';
    tty_emit_csi(buf, 'm');
}

/* Truecolor (24-bit) FG: CSI 38;2;r;g;bm */
static inline void tty_fg_rgb(unsigned int r, unsigned int g, unsigned int b) {
    char buf[32];
    int p = 0;
    p += append_uint(buf + p, 38); buf[p++] = ';';
    buf[p++] = '2'; buf[p++] = ';';
    p += append_uint(buf + p, r & 0xFF); buf[p++] = ';';
    p += append_uint(buf + p, g & 0xFF); buf[p++] = ';';
    p += append_uint(buf + p, b & 0xFF);
    buf[p] = '\0';
    tty_emit_csi(buf, 'm');
}

/* Title (OSC sequence): ESC ] 0 ; title BEL */
static inline void tty_set_title(const char *title) {
    tty_emit_esc(); /* ESC */
    putc_tty(']');
    putc_tty('0');
    putc_tty(';');
    if (title) tty_puts(title);
    putc_tty('\x07'); /* BEL */
}

#endif /* ANSI_TTY_H */

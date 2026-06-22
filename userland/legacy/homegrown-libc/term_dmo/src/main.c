/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/legacy/homegrown-libc/term_dmo/src/main.c
 * Layer: Userland / program
 * Description: ArmOS userspace program or support module.
 */

#include <stdio.h>
#include <unistd.h>   /* usleep */
#include <string.h>
#include <ansi_term.h>

/* Draw a simple box at (r,c) of given size and title */
void draw_box(int r, int c, int h, int w, const char *title) {
    if (h < 3 || w < 4) return;
    CURSOR_POS(r, c);
    putc_tty('+');
    for (int i = 0; i < w-2; ++i) putc_tty('-');
    putc_tty('+');

    for (int y = 1; y < h-1; ++y) {
        CURSOR_POS(r+y, c);
        putc_tty('|');
        for (int i = 0; i < w-2; ++i) putc_tty(' ');
        putc_tty('|');
    }

    CURSOR_POS(r+h-1, c);
    putc_tty('+');
    for (int i = 0; i < w-2; ++i) putc_tty('-');
    putc_tty('+');

    if (title && title[0]) {
        CURSOR_POS(r, c + 2);
        SGR_BOLD(); FG_CYAN();
        printf(" %s ", title);
        SGR_RESET();
    }
}

/* Simple progress bar inside box */
void progress_bar(int r, int c, int w, int ratio) {
    int inner = w - 2;
    int fill = (int)(inner * ratio + 1/2);
    CURSOR_POS(r, c+1);
    for (int i = 0; i < inner; ++i) {
        if (i < fill) { FG_GREEN(); putc_tty('='); }
        else { FG_WHITE(); putc_tty(' '); }
    }
    SGR_RESET();
}

/* Demo main */
int main(void) {
    CLEAR_SCREEN();
    CURSOR_HIDE();
    set_term_title("Term Demo");

    CURSOR_POS(1,1);
    SGR_BOLD(); FG_YELLOW();
    printf("ANSI/CSI demo — press Ctrl-C to exit\n");
    SGR_RESET();

    draw_box(3, 4, 8, 60, "Status");
    draw_box(12, 4, 6, 60, "Log");

    for (int i = 0; i <= 100; ++i) {
        unsigned int r = i / 100;
        progress_bar(4, 5, 58, r); /* inside first box starting at (4,5) width 58 */
        CURSOR_POS(5, 6);
        printf("Progress: %3d%%   ", i);

        /* write a log line occasionally */
        if (i % 20 == 0) {
            CURSOR_POS(13 + (i/20), 6);
            FG_MAGENTA();
            printf("Event: step %d\n", i);
            SGR_RESET();
        }

        pflush();
        for(int i=0; i < 100000; i++); /* 100 ms */
    }

    /* reset & cleanup */
    CURSOR_POS(20,1);
    SGR_RESET();
    CURSOR_SHOW();
    printf("\nDone.\n");
    return 0;
}

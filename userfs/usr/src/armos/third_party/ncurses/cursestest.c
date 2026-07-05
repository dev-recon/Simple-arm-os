/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: third_party/ncurses/cursestest.c
 * Layer: Userland / external port smoke test
 * Description: Minimal ncurses runtime test for ArmOS TTY and ANSI behavior.
 */

#include <curses.h>
#include <stdlib.h>

static void draw_status(int row, int col, int ch)
{
    int max_y;
    int max_x;

    getmaxyx(stdscr, max_y, max_x);
    erase();

    if (has_colors()) {
        attron(COLOR_PAIR(1));
        mvprintw(0, 0, "ArmOS ncurses smoke test");
        attroff(COLOR_PAIR(1));
    } else {
        mvprintw(0, 0, "ArmOS ncurses smoke test");
    }

    mvprintw(2, 0, "TERM=%s", getenv("TERM") ? getenv("TERM") : "(unset)");
    mvprintw(3, 0, "screen: %d rows x %d cols", max_y, max_x);
    mvprintw(5, 0, "Use arrows to move '@'. Press q to quit.");
    mvprintw(6, 0, "Last key: %d", ch);

    if (row < 8)
        row = 8;
    if (row >= max_y)
        row = max_y - 1;
    if (col < 0)
        col = 0;
    if (col >= max_x)
        col = max_x - 1;

    if (has_colors())
        attron(COLOR_PAIR(2));
    mvaddch(row, col, '@');
    if (has_colors())
        attroff(COLOR_PAIR(2));

    refresh();
}

int main(void)
{
    int row = 10;
    int col = 10;
    int ch = 0;

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    timeout(100);

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);
        init_pair(2, COLOR_YELLOW, COLOR_BLUE);
    }

    draw_status(row, col, ch);

    while ((ch = getch()) != 'q') {
        switch (ch) {
        case KEY_UP:
            row--;
            break;
        case KEY_DOWN:
            row++;
            break;
        case KEY_LEFT:
            col--;
            break;
        case KEY_RIGHT:
            col++;
            break;
        default:
            break;
        }
        draw_status(row, col, ch);
    }

    endwin();
    return 0;
}

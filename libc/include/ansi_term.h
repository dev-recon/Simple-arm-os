#ifndef ANSI_TERM_H
#define ANSI_TERM_H

#include <stdio.h>

/* ESC / CSI helpers */
#define ESC "\x1b"
#define CSI "\x1b["

/* Cursor */
#define CURSOR_HOME()            printf(CSI "H")
#define CURSOR_POS(r,c)          printf(CSI "%d;%dH", (r), (c))
#define CURSOR_SAVE()            printf(CSI "s")
#define CURSOR_RESTORE()         printf(CSI "u")
#define CURSOR_HIDE()            printf(CSI "?25l")
#define CURSOR_SHOW()            printf(CSI "?25h")

/* Clear */
#define CLEAR_SCREEN()           printf(CSI "2J")
#define CLEAR_LINE()             printf(CSI "2K")
#define CLEAR_TO_EOL()           printf(CSI "0K")
#define CLEAR_FROM_CURSOR_DOWN() printf(CSI "0J")

/* SGR text attributes */
#define SGR_RESET()              printf(CSI "0m")
#define SGR_BOLD()               printf(CSI "1m")
#define SGR_UNDERLINE()          printf(CSI "4m")
#define SGR_REVERSE()            printf(CSI "7m")

/* Basic 8 colors foreground/background */
#define FG_BLACK()   printf(CSI "30m")
#define FG_RED()     printf(CSI "31m")
#define FG_GREEN()   printf(CSI "32m")
#define FG_YELLOW()  printf(CSI "33m")
#define FG_BLUE()    printf(CSI "34m")
#define FG_MAGENTA() printf(CSI "35m")
#define FG_CYAN()    printf(CSI "36m")
#define FG_WHITE()   printf(CSI "37m")

#define BG_BLACK()   printf(CSI "40m")
#define BG_RED()     printf(CSI "41m")
#define BG_GREEN()   printf(CSI "42m")
#define BG_YELLOW()  printf(CSI "43m")
#define BG_BLUE()    printf(CSI "44m")
#define BG_MAGENTA() printf(CSI "45m")
#define BG_CYAN()    printf(CSI "46m")
#define BG_WHITE()   printf(CSI "47m")

/* Bright via single code */
#define FG_BRIGHT(n) printf(CSI "%dm", 90 + (n))  /* n:0..7 => 90..97 */
#define BG_BRIGHT(n) printf(CSI "%dm", 100 + (n)) /* n:0..7 => 100..107 */

/* 256 color helpers:
   fg: printf(CSI "38;5;{n}m"), bg: "48;5;{n}m" */
static inline void fg256(int n) { printf(CSI "38;5;%dm", n); }
static inline void bg256(int n) { printf(CSI "48;5;%dm", n); }

/* Truecolor (24-bit): fg/bg */
static inline void fg_rgb(int r,int g,int b) { printf(CSI "38;2;%d;%d;%dm", r,g,b); }
static inline void bg_rgb(int r,int g,int b) { printf(CSI "48;2;%d;%d;%dm", r,g,b); }

/* Title (OSC sequence) */
static inline void set_term_title(const char *title) {
    /* ESC ] 0 ; title BEL */
    printf("\x1b]0;%s\x07", title ? title : "");
}

/* Convenience: print colored string then reset */
static inline void print_colored(const char *s, const char *fg_code) {
    printf("%s%s" CSI "0m", fg_code, s);
}

#endif /* ANSI_TERM_H */

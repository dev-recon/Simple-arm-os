#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define DEMO_ROWS 24
#define DEMO_COLS 80

static struct termios saved_termios;
static int have_saved_termios;

static void putstr(const char *s)
{
    while (*s) {
        write(STDOUT_FILENO, s, 1);
        s++;
    }
}

static void move_cursor(int row, int col)
{
    char seq[32];

    snprintf(seq, sizeof(seq), "\033[%d;%dH", row, col);
    putstr(seq);
}

static void restore_terminal(void)
{
    if (have_saved_termios)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);

    putstr("\033[?25h");
    putstr("\033[?1049l");
}

static int enter_raw_screen(void)
{
    struct termios raw;

    if (tcgetattr(STDIN_FILENO, &saved_termios) < 0) {
        printf("screen_demo: tcgetattr failed\n");
        return -1;
    }

    have_saved_termios = 1;
    raw = saved_termios;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        printf("screen_demo: tcsetattr failed\n");
        return -1;
    }

    putstr("\033[?1049h");
    putstr("\033[?25l");
    putstr("\033[2J");
    putstr("\033[H");
    return 0;
}

static void draw_box(void)
{
    int row;
    int col;

    putstr("\033[2J");
    move_cursor(1, 1);
    putstr("\033[1;36mArmOS VT100 screen demo\033[0m");
    move_cursor(2, 1);
    putstr("Arrows move the marker. Press q or Ctrl-C to quit.");

    for (col = 1; col <= DEMO_COLS; col++) {
        move_cursor(4, col);
        putstr("-");
        move_cursor(DEMO_ROWS - 1, col);
        putstr("-");
    }

    for (row = 4; row <= DEMO_ROWS - 1; row++) {
        move_cursor(row, 1);
        putstr("|");
        move_cursor(row, DEMO_COLS);
        putstr("|");
    }

    move_cursor(4, 1);
    putstr("+");
    move_cursor(4, DEMO_COLS);
    putstr("+");
    move_cursor(DEMO_ROWS - 1, 1);
    putstr("+");
    move_cursor(DEMO_ROWS - 1, DEMO_COLS);
    putstr("+");
}

static void draw_marker(int row, int col)
{
    move_cursor(row, col);
    putstr("\033[1;32m@\033[0m");
}

static void clear_marker(int row, int col)
{
    move_cursor(row, col);
    putstr(" ");
}

static void draw_status(int row, int col, const char *key)
{
    char buf[96];

    move_cursor(DEMO_ROWS, 1);
    putstr("\033[K");
    snprintf(buf, sizeof(buf), "pos=(%d,%d) last=%s", row, col, key);
    putstr(buf);
}

static int read_key(char *name, int name_size)
{
    unsigned char c;
    ssize_t n;

    n = read(STDIN_FILENO, &c, 1);
    if (n <= 0)
        return 0;

    if (c == 0x1b) {
        unsigned char seq[2];

        if (read(STDIN_FILENO, &seq[0], 1) == 1 &&
            read(STDIN_FILENO, &seq[1], 1) == 1 &&
            seq[0] == '[') {
            switch (seq[1]) {
            case 'A':
                snprintf(name, name_size, "Up");
                return 'U';
            case 'B':
                snprintf(name, name_size, "Down");
                return 'D';
            case 'C':
                snprintf(name, name_size, "Right");
                return 'R';
            case 'D':
                snprintf(name, name_size, "Left");
                return 'L';
            default:
                snprintf(name, name_size, "ESC[%c", seq[1]);
                return 0;
            }
        }

        snprintf(name, name_size, "ESC");
        return 0;
    }

    if (c == 'q') {
        snprintf(name, name_size, "q");
        return 'q';
    }

    if (c == 0x03) {
        snprintf(name, name_size, "Ctrl-C");
        return 'q';
    }

    if (c >= 0x20 && c < 0x7f)
        snprintf(name, name_size, "%c", c);
    else
        snprintf(name, name_size, "0x%02x", c);

    return 0;
}

int main(void)
{
    int row = DEMO_ROWS / 2;
    int col = DEMO_COLS / 2;
    char key[32] = "none";

    if (enter_raw_screen() < 0)
        return 1;

    atexit(restore_terminal);

    draw_box();
    draw_marker(row, col);
    draw_status(row, col, key);

    while (1) {
        int action = read_key(key, sizeof(key));

        clear_marker(row, col);

        if (action == 'q')
            break;
        if (action == 'U' && row > 5)
            row--;
        else if (action == 'D' && row < DEMO_ROWS - 2)
            row++;
        else if (action == 'L' && col > 2)
            col--;
        else if (action == 'R' && col < DEMO_COLS - 1)
            col++;

        draw_marker(row, col);
        draw_status(row, col, key);
    }

    return 0;
}

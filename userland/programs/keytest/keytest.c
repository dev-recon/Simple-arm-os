#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_termios;
static int have_saved_termios;

static void restore_terminal(void)
{
    if (have_saved_termios)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
}

static const char *key_name(unsigned char c)
{
    switch (c) {
    case 0x03: return "Ctrl-C";
    case 0x04: return "Ctrl-D";
    case 0x09: return "Tab";
    case 0x0d: return "CR";
    case 0x0a: return "LF";
    case 0x1b: return "ESC";
    case 0x7f: return "DEL";
    default:
        break;
    }

    if (c < 0x20)
        return "control";
    if (c >= 0x20 && c < 0x7f)
        return "printable";
    return "extended";
}

static int enter_rawish_mode(void)
{
    struct termios raw;

    if (tcgetattr(STDIN_FILENO, &saved_termios) < 0) {
        printf("keytest: tcgetattr failed\n");
        return -1;
    }

    have_saved_termios = 1;
    raw = saved_termios;

    /*
     * Keep ISIG enabled for now: this validates byte-at-a-time input while
     * preserving Ctrl+C as an emergency exit during early TTY work.
     */
    raw.c_lflag &= ~(ICANON | ECHO);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        printf("keytest: tcsetattr failed\n");
        return -1;
    }

    return 0;
}

int main(void)
{
    unsigned int count = 0;

    if (enter_rawish_mode() < 0)
        return 1;

    atexit(restore_terminal);

    printf("keytest: raw input test. Press q or Ctrl-D to quit.\n");
    printf("keytest: Ctrl+C is intentionally still handled by the TTY.\n");

    while (1) {
        unsigned char c;
        ssize_t n = read(STDIN_FILENO, &c, 1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            printf("keytest: read failed errno=%d\n", errno);
            return 1;
        }

        if (n == 0)
            continue;

        count++;
        if (c >= 0x20 && c < 0x7f) {
            printf("%04u: dec=%3u hex=0x%02x char='%c' %s\n",
                   count, (unsigned)c, (unsigned)c, c, key_name(c));
        } else {
            printf("%04u: dec=%3u hex=0x%02x %s\n",
                   count, (unsigned)c, (unsigned)c, key_name(c));
        }

        if (c == 'q' || c == 0x04)
            break;
    }

    printf("keytest: done\n");
    return 0;
}

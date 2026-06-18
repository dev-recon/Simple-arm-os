#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_termios;
static int have_saved_termios;
static int failures;

static void restore_terminal(void)
{
    if (have_saved_termios)
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
}

static void ok(const char *name)
{
    printf("\033[1;32m[OK]\033[0m %s\n", name);
}

static void fail(const char *name, int detail)
{
    failures++;
    printf("\033[1;31m[FAIL]\033[0m %s (%d)\n", name, detail);
}

static void expect_true(int cond, const char *name, int detail)
{
    if (cond)
        ok(name);
    else
        fail(name, detail);
}

int main(void)
{
    struct termios tio;
    struct termios raw;
    struct termios check;
    unsigned char c = 0;
    ssize_t n;

    printf("ttytest: termios smoke test\n");

    if (tcgetattr(STDIN_FILENO, &saved_termios) < 0) {
        fail("tcgetattr stdin", errno);
        return 1;
    }
    have_saved_termios = 1;
    atexit(restore_terminal);

    tio = saved_termios;
    ok("tcgetattr stdin");
    expect_true((tio.c_lflag & ICANON) != 0, "default ICANON set", (int)tio.c_lflag);
    expect_true((tio.c_lflag & ISIG) != 0, "default ISIG set", (int)tio.c_lflag);
    expect_true((tio.c_iflag & ICRNL) != 0, "default ICRNL set", (int)tio.c_iflag);
    expect_true((tio.c_oflag & OPOST) != 0, "default OPOST set", (int)tio.c_oflag);
    expect_true((tio.c_oflag & ONLCR) != 0, "default ONLCR set", (int)tio.c_oflag);
    expect_true(tio.c_cc[VMIN] == 1, "default VMIN is 1", tio.c_cc[VMIN]);
    expect_true(tio.c_cc[VINTR] == 3, "default VINTR is Ctrl-C", tio.c_cc[VINTR]);

    if (tcflush(STDIN_FILENO, TCIFLUSH) == 0)
        ok("tcflush input queue");
    else
        fail("tcflush input queue", errno);

    raw = saved_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_iflag &= ~ICRNL;
    raw.c_oflag &= ~OPOST;
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
        fail("tcsetattr raw timeout mode", errno);
        return 1;
    }
    ok("tcsetattr raw timeout mode");

    memset(&check, 0, sizeof(check));
    if (tcgetattr(STDIN_FILENO, &check) == 0) {
        ok("tcgetattr observes raw mode");
        expect_true((check.c_lflag & ICANON) == 0,
                    "raw mode clears ICANON", (int)check.c_lflag);
        expect_true((check.c_lflag & ECHO) == 0,
                    "raw mode clears ECHO", (int)check.c_lflag);
        expect_true((check.c_iflag & ICRNL) == 0,
                    "raw mode clears ICRNL", (int)check.c_iflag);
        expect_true((check.c_oflag & OPOST) == 0,
                    "raw mode clears OPOST", (int)check.c_oflag);
        expect_true(check.c_cc[VMIN] == 0,
                    "raw mode keeps VMIN=0", check.c_cc[VMIN]);
        expect_true(check.c_cc[VTIME] == 1,
                    "raw mode keeps VTIME=1", check.c_cc[VTIME]);
    } else {
        fail("tcgetattr observes raw mode", errno);
    }

    errno = 0;
    n = read(STDIN_FILENO, &c, 1);
    if (n == 0)
        ok("read timeout returns 0 with VMIN=0/VTIME=1");
    else if (n == 1)
        printf("\033[1;33m[WARN]\033[0m read consumed pending byte 0x%02x\n", c);
    else
        fail("read timeout returns 0 with VMIN=0/VTIME=1", errno);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios) == 0)
        ok("tcsetattr restores terminal");
    else
        fail("tcsetattr restores terminal", errno);

    have_saved_termios = 0;
    printf("ttytest: %s\n", failures ? "failed" : "all tests passed");
    return failures ? 1 : 0;
}

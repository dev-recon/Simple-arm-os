/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/keytest/keytest.c
 * Layer: Userland / test or sample program
 * Description: Userland test, diagnostic, or sample application.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_termios;
static int have_saved_termios;
static FILE *log_file;

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

static void usage(void)
{
    printf("usage: keytest [-o file]\n");
    printf("       Press q or Ctrl-D to quit. Ctrl-C remains an emergency exit.\n");
}

static void log_line(const char *line)
{
    printf("%s", line);
    fflush(stdout);

    if (log_file) {
        fputs(line, log_file);
        fflush(log_file);
    }
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

int main(int argc, char **argv)
{
    unsigned int count = 0;
    const char *log_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                usage();
                return 1;
            }
            log_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else {
            usage();
            return 1;
        }
    }

    if (log_path) {
        log_file = fopen(log_path, "w");
        if (!log_file) {
            printf("keytest: cannot open %s: errno=%d\n", log_path, errno);
            return 1;
        }
    }

    if (enter_rawish_mode() < 0)
        return 1;

    atexit(restore_terminal);

    log_line("keytest: raw input test. Press q or Ctrl-D to quit.\n");
    log_line("keytest: Ctrl+C is intentionally still handled by the TTY.\n");
    if (log_path) {
        char line[160];
        snprintf(line, sizeof(line), "keytest: logging to %s\n", log_path);
        log_line(line);
    }

    while (1) {
        unsigned char c;
        char line[160];
        ssize_t n = read(STDIN_FILENO, &c, 1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            snprintf(line, sizeof(line), "keytest: read failed errno=%d\n", errno);
            log_line(line);
            return 1;
        }

        if (n == 0)
            continue;

        count++;
        if (c >= 0x20 && c < 0x7f) {
            snprintf(line, sizeof(line),
                     "%04u: dec=%3u hex=0x%02x char='%c' %s\n",
                     count, (unsigned)c, (unsigned)c, c, key_name(c));
        } else {
            snprintf(line, sizeof(line),
                     "%04u: dec=%3u hex=0x%02x %s\n",
                     count, (unsigned)c, (unsigned)c, key_name(c));
        }
        log_line(line);

        if (c == 'q' || c == 0x04)
            break;
    }

    log_line("keytest: done\n");
    if (log_file)
        fclose(log_file);
    return 0;
}

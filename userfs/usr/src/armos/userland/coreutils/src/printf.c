/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/printf.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int put_escape(const char **fmt)
{
    const char *p = *fmt + 1;

    switch (*p) {
    case 'n': putchar('\n'); break;
    case 'r': putchar('\r'); break;
    case 't': putchar('\t'); break;
    case '\\': putchar('\\'); break;
    case '0': return 1;
    default:
        if (*p)
            putchar(*p);
        else
            putchar('\\');
        break;
    }

    *fmt = *p ? p : p - 1;
    return 0;
}

int main(int argc, char **argv)
{
    const char *fmt;
    int arg = 2;

    if (argc < 2) {
        printf("usage: printf FORMAT [ARG...]\n");
        return 1;
    }

    fmt = argv[1];
    for (const char *p = fmt; *p; p++) {
        if (*p == '\\') {
            if (put_escape(&p))
                return 0;
            continue;
        }
        if (*p != '%') {
            putchar(*p);
            continue;
        }
        p++;
        if (*p == '%') {
            putchar('%');
        } else if (*p == 's') {
            fputs(arg < argc ? argv[arg++] : "", stdout);
        } else if (*p == 'd' || *p == 'i') {
            printf("%d", arg < argc ? atoi(argv[arg++]) : 0);
        } else if (*p == 'u') {
            printf("%u", arg < argc ? (unsigned)strtoul(argv[arg++], NULL, 0) : 0);
        } else if (*p == 'x') {
            printf("%x", arg < argc ? (unsigned)strtoul(argv[arg++], NULL, 0) : 0);
        } else if (*p == 'c') {
            putchar(arg < argc && argv[arg][0] ? argv[arg++][0] : '\0');
        } else {
            putchar('%');
            if (*p)
                putchar(*p);
            else
                break;
        }
    }

    return 0;
}

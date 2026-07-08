/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/uname.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

static void usage(void)
{
    fprintf(stderr, "usage: uname [-amnoprsv]\n");
}

static void print_field(const char *field, int *first)
{
    if (!*first)
        putchar(' ');
    fputs(field, stdout);
    *first = 0;
}

int main(int argc, char **argv)
{
    int show_sysname = 0;
    int show_nodename = 0;
    int show_release = 0;
    int show_version = 0;
    int show_machine = 0;
    int show_processor = 0;
    int show_os = 0;
    int first = 1;
    struct utsname u;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (arg[0] != '-' || arg[1] == '\0') {
            usage();
            return 1;
        }

        for (int j = 1; arg[j] != '\0'; j++) {
            switch (arg[j]) {
            case 'a':
                show_sysname = 1;
                show_nodename = 1;
                show_release = 1;
                show_version = 1;
                show_machine = 1;
                show_processor = 1;
                show_os = 1;
                break;
            case 's':
                show_sysname = 1;
                break;
            case 'n':
                show_nodename = 1;
                break;
            case 'r':
                show_release = 1;
                break;
            case 'v':
                show_version = 1;
                break;
            case 'm':
                show_machine = 1;
                break;
            case 'p':
                show_processor = 1;
                break;
            case 'o':
                show_os = 1;
                break;
            default:
                usage();
                return 1;
            }
        }
    }

    if (uname(&u) < 0) {
        perror("uname");
        return 1;
    }

    if (!show_sysname && !show_nodename && !show_release && !show_version &&
        !show_machine && !show_processor && !show_os)
        show_sysname = 1;

    if (show_sysname)
        print_field(u.sysname, &first);
    if (show_nodename)
        print_field(u.nodename, &first);
    if (show_release)
        print_field(u.release, &first);
    if (show_version)
        print_field(u.version, &first);
    if (show_machine)
        print_field(u.machine, &first);
    if (show_processor)
        print_field("arm", &first);
    if (show_os)
        print_field(u.sysname, &first);

    putchar('\n');

    return 0;
}

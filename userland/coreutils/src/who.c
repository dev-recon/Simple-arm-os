/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/who.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arm_os_abi.h"

static struct sysinfo_response who_sysinfo;

static const char *user_name(unsigned uid)
{
    static char names[8][32];
    static int slot;
    FILE *f = fopen("/etc/passwd", "r");
    char line[256];
    char *out = names[slot++ % 8];

    snprintf(out, 32, "%u", uid);
    if (!f)
        return out;

    while (fgets(line, sizeof(line), f)) {
        char *name = strtok(line, ":");
        char *x = strtok(NULL, ":");
        char *uid_s = strtok(NULL, ":");
        (void)x;
        if (name && uid_s && (unsigned)strtoul(uid_s, NULL, 10) == uid) {
            snprintf(out, 32, "%s", name);
            break;
        }
    }
    fclose(f);
    return out;
}

int main(void)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char tbuf[32] = "Jan  1 00:00";

    if (tm)
        strftime(tbuf, sizeof(tbuf), "%b %e %H:%M", tm);

    if (getsysinfo(&who_sysinfo) < 0) {
        printf("who: cannot read process table\n");
        return 1;
    }

    for (int i = 0; i < who_sysinfo.proc_count; i++) {
        struct proc_info *p = &who_sysinfo.procs[i];
        if (p->pid <= 0 || p->tty < 0 || p->type != 'P')
            continue;
        if (strcmp(p->name, "mash") == 0 || strstr(p->name, "sh")) {
            printf("%-8s tty%d         %s\n", user_name(p->uid), p->tty, tbuf);
        }
    }

    return 0;
}

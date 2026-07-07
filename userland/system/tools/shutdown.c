/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/tools/shutdown.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void write_all(int fd, const char *s)
{
    size_t len;

    if (!s)
        return;

    len = strlen(s);
    while (len > 0) {
        ssize_t written = write(fd, s, len);
        if (written <= 0)
            return;
        s += written;
        len -= (size_t)written;
    }
}

int main(void)
{
    write_all(STDOUT_FILENO, "shutdown: powering off system...\n");

    /*
     * Notify userland init first so it can stop login shells and avoid respawn
     * noise during the kernel-led poweroff sequence.  Give mash enough time to
     * handle SIGTERM and persist command history before the kernel starts its
     * own signal/sync/unmount sequence.
     */
    if (kill(1, SIGTERM) == 0)
        usleep(300000);

    sys_shutdown();
    write_all(STDOUT_FILENO, "shutdown: kernel poweroff returned unexpectedly\n");
    return 1;
}

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
#include <unistd.h>

int main(void)
{
    printf("shutdown: powering off system...\n");
    sys_shutdown();
    printf("shutdown: kernel poweroff returned unexpectedly\n");
    return 1;
}

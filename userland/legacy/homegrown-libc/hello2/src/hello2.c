/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/legacy/homegrown-libc/hello2/src/hello2.c
 * Layer: Userland / program
 * Description: ArmOS userspace program or support module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 22 ;

    printf("Hello from userspace version %d!\n", version);
    printf("My PID: %d\n", getpid());
    printf("Exiting for now with the value %d\n", version);

    exit(version);
}
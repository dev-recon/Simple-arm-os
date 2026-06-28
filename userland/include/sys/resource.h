/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/resource.h
 * Layer: Userland / POSIX compatibility
 * Description: Minimal resource-priority declarations for newlib programs.
 */

#ifndef ARMOS_SYS_RESOURCE_H
#define ARMOS_SYS_RESOURCE_H

#include <sys/types.h>

#define PRIO_PROCESS 0
#define PRIO_PGRP    1
#define PRIO_USER    2

int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);

#endif /* ARMOS_SYS_RESOURCE_H */

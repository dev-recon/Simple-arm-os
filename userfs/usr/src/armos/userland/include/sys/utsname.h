/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/utsname.h
 * Layer: Userland / POSIX compatibility
 * Description: Minimal uname(2) declarations.
 */

#ifndef ARMOS_SYS_UTSNAME_H
#define ARMOS_SYS_UTSNAME_H

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

int uname(struct utsname *name);

#endif /* ARMOS_SYS_UTSNAME_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/include/sys/ioctl.h
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

#define TCGETS      0x5401
#define TCSETS      0x5402
#define TCSETSW     0x5403
#define TCSETSF     0x5404

int ioctl(int fd, unsigned long request, ...);

#endif /* _SYS_IOCTL_H */

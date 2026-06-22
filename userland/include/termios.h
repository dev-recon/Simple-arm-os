/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/termios.h
 * Layer: Userland / public header
 * Description: Userspace ABI or library declarations for ArmOS programs.
 */

#ifndef ARM_OS_NEWLIB_TERMIOS_H
#define ARM_OS_NEWLIB_TERMIOS_H

#include <sys/ioctl.h>

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

#define NCCS 32

#define VINTR     0
#define VQUIT     1
#define VERASE    2
#define VKILL     3
#define VEOF      4
#define VTIME     5
#define VMIN      6
#define VSTART    8
#define VSTOP     9
#define VSUSP     10
#define VEOL      11
#define VREPRINT  12
#define VDISCARD  13
#define VWERASE   14
#define VLNEXT    15
#define VEOL2     16

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[NCCS];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

#define ECHO    0x0001
#define ICANON  0x0002
#define ISIG    0x0004
#define IEXTEN  0x0008
#define ECHOE   0x0010
#define ECHOK   0x0020
#define ECHOCTL 0x0040
#define ECHOKE  0x0080

#define INLCR   0x00000040
#define IGNCR   0x00000080
#define ICRNL   0x00000100
#define IXOFF   0x00000400
#define BRKINT  0x00000002
#define INPCK   0x00000010
#define ISTRIP  0x00000020
#define IXON    0x00000200

#define OPOST   0x00000001
#define ONLCR   0x00000002
#define OCRNL   0x00000004
#define ONOCR   0x00000008
#define ONLRET  0x00000010

#define CS8     0x00000300
#define CREAD   0x00000800
#define HUPCL   0x00001000

#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

int tcgetattr(int fd, struct termios *termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int tcflush(int fd, int queue_selector);
int tcdrain(int fd);

#endif

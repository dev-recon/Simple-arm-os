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
#define NOFLSH  0x0100
#define ECHOE   0x0010
#define ECHOK   0x0020
#define ECHOCTL 0x0040
#define ECHOKE  0x0080
#define ECHONL  0x0200

#define INLCR   0x00000040
#define IGNCR   0x00000080
#define ICRNL   0x00000100
#define IXOFF   0x00000400
#define BRKINT  0x00000002
#define PARMRK  0x00000008
#define INPCK   0x00000010
#define ISTRIP  0x00000020
#define IXON    0x00000200

#define OPOST   0x00000001
#define ONLCR   0x00000002
#define OCRNL   0x00000004
#define ONOCR   0x00000008
#define ONLRET  0x00000010

#define CS5     0x00000000
#define CS6     0x00000100
#define CS7     0x00000200
#define CS8     0x00000300
#define CSIZE   0x00000300
#define CREAD   0x00000800
#define HUPCL   0x00001000

#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

#define B0       0
#define B50      50
#define B75      75
#define B110     110
#define B134     134
#define B150     150
#define B200     200
#define B300     300
#define B600     600
#define B1200    1200
#define B1800    1800
#define B2400    2400
#define B4800    4800
#define B9600    9600
#define B19200   19200
#define B38400   38400
#define B57600   57600
#define B115200  115200

static inline speed_t cfgetispeed(const struct termios *termios_p)
{
    return termios_p ? termios_p->c_ispeed : 0;
}

static inline speed_t cfgetospeed(const struct termios *termios_p)
{
    return termios_p ? termios_p->c_ospeed : 0;
}

static inline int cfsetispeed(struct termios *termios_p, speed_t speed)
{
    if (!termios_p)
        return -1;
    termios_p->c_ispeed = speed;
    return 0;
}

static inline int cfsetospeed(struct termios *termios_p, speed_t speed)
{
    if (!termios_p)
        return -1;
    termios_p->c_ospeed = speed;
    return 0;
}

int tcgetattr(int fd, struct termios *termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int tcflush(int fd, int queue_selector);
int tcdrain(int fd);

#endif

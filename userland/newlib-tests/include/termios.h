#ifndef ARM_OS_NEWLIB_TERMIOS_H
#define ARM_OS_NEWLIB_TERMIOS_H

#include <sys/ioctl.h>

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

#define NCCS 32

#define VMIN  16
#define VTIME 17

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

#define BRKINT  0x00000002
#define INPCK   0x00000010
#define ISTRIP  0x00000020
#define ICRNL   0x00000100
#define IXON    0x00000200

#define OPOST   0x00000001

#define CS8     0x00000300

int tcgetattr(int fd, struct termios *termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);

#endif

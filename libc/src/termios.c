#include <termios.h>
#include <unistd.h>

int tcgetattr(int fd, struct termios* termios_p)
{
    return ioctl(fd, TCGETS, termios_p);
}

int tcsetattr(int fd, int optional_actions, const struct termios* termios_p)
{
    int request;

    switch (optional_actions) {
    case TCSANOW:
        request = TCSETS;
        break;
    case TCSADRAIN:
        request = TCSETSW;
        break;
    case TCSAFLUSH:
        request = TCSETSF;
        break;
    default:
        request = TCSETS;
        break;
    }

    return ioctl(fd, request, termios_p);
}

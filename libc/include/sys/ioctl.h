#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

#define TCGETS      0x5401
#define TCSETS      0x5402
#define TCSETSW     0x5403
#define TCSETSF     0x5404

int ioctl(int fd, unsigned long request, ...);

#endif /* _SYS_IOCTL_H */

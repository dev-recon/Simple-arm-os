#ifndef _KERNEL_POWER_H
#define _KERNEL_POWER_H

void kernel_poweroff(void) __attribute__((noreturn));
int sys_shutdown(void);

#endif

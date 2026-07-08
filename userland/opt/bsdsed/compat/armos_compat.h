#ifndef ARMOS_BSDSED_COMPAT_H
#define ARMOS_BSDSED_COMPAT_H

#include <stdint.h>
#include <sys/cdefs.h>
#include <wchar.h>

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef __UNCONST
#define __UNCONST(a) ((void *)(uintptr_t)(const void *)(a))
#endif

#ifndef REG_GNU
#define REG_GNU 0
#endif

#ifndef _POSIX2_LINE_MAX
#define _POSIX2_LINE_MAX 2048
#endif

int wcwidth(wchar_t wc);

#endif /* ARMOS_BSDSED_COMPAT_H */

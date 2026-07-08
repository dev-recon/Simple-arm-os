#ifndef ARMOS_BSDAWK_COMPAT_H
#define ARMOS_BSDAWK_COMPAT_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef HAS_ISBLANK
#define HAS_ISBLANK 1
#endif

#endif

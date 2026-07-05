/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/fnmatch.h
 * Layer: Userland / public header
 * Description: Compatibility overlay for newlib fnmatch declarations.
 */

#ifndef ARM_OS_NEWLIB_FNMATCH_H
#define ARM_OS_NEWLIB_FNMATCH_H

#include_next <fnmatch.h>

/*
 * gnulib users such as nano expect the GNU extension flag FNM_EXTMATCH to be
 * present when compiling their replacement fnmatch code.  Newlib exposes the
 * core POSIX flags and a subset of GNU names, so keep its ABI and fill only the
 * missing constants here.
 */
#ifndef FNM_LEADING_DIR
#define FNM_LEADING_DIR 0x08
#endif

#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0x10
#endif

#ifndef FNM_IGNORECASE
#define FNM_IGNORECASE FNM_CASEFOLD
#endif

#ifndef FNM_FILE_NAME
#define FNM_FILE_NAME FNM_PATHNAME
#endif

#ifndef FNM_EXTMATCH
#define FNM_EXTMATCH 0x20
#endif

#endif

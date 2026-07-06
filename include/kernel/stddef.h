/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/stddef.h
 * Layer: Kernel / basic C definitions
 *
 * Responsibilities:
 * - Provide freestanding definitions normally supplied by <stddef.h>.
 * - Keep generic C utility macros independent from the global kernel header.
 */

#ifndef KERNEL_STDDEF_H
#define KERNEL_STDDEF_H

#include <kernel/types.h>

#ifndef offsetof
#if defined(__GNUC__) || defined(__clang__)
#define offsetof(type, member) __builtin_offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)&((type*)0)->member)
#endif
#endif

#endif /* KERNEL_STDDEF_H */

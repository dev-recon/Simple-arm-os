/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/compiler.h
 * Layer: Kernel / compiler contract
 *
 * Responsibilities:
 * - Centralize compiler attributes used by portable kernel code.
 * - Keep section-placement and alignment annotations out of generic
 *   subsystem headers.
 */

#ifndef KERNEL_COMPILER_H
#define KERNEL_COMPILER_H

#include <kernel/types.h>

/* Linker-script sections. */
#define __init_code             __attribute__((section(".text.init")))
#define __init_data             __attribute__((section(".data.init")))
#define __kernel_data           __attribute__((section(".data.kernel")))

/* Common alignment annotations. */
#define __aligned_4             __attribute__((aligned(4)))
#define __aligned_8             __attribute__((aligned(8)))
#define __aligned_page          __attribute__((aligned(PAGE_SIZE)))
#define __cache_aligned         __attribute__((aligned(CACHE_LINE_SIZE)))

/* Function and value properties. */
#define __always_inline         __attribute__((always_inline))
#define __noinline              __attribute__((noinline))
#define __pure                  __attribute__((pure))
#define __const                 __attribute__((const))

#endif /* KERNEL_COMPILER_H */

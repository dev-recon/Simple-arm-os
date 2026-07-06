/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/user_layout.h
 * Layer: Kernel / architecture compatibility
 *
 * Responsibilities:
 * - Expose architecture-provided user virtual layout constants through stable
 *   generic kernel names.
 * - Keep generic subsystems from depending directly on asm/user_layout.h.
 *
 * Notes:
 * - New architectures should provide the ARCH_USER_* constants in their own
 *   asm/user_layout.h backend.
 */

#ifndef _KERNEL_USER_LAYOUT_H
#define _KERNEL_USER_LAYOUT_H

#include <asm/user_layout.h>

/*
 * Compatibility aliases for the user virtual layout.  The concrete addresses
 * are supplied by the active architecture backend.
 */
#define USER_SPACE_START         ARCH_USER_SPACE_START
#define USER_STACK_TOP           ARCH_USER_STACK_TOP
#define USER_STACK_SIZE          ARCH_USER_STACK_SIZE
#define USER_STACK_BOTTOM        ARCH_USER_STACK_BOTTOM
#define USER_HEAP_START          ARCH_USER_HEAP_START
#define USER_SHM_START           ARCH_USER_SHM_START
#define USER_SHM_END             ARCH_USER_SHM_END
#define USER_HEAP_END            ARCH_USER_HEAP_END
#define USER_SPACE_END           ARCH_USER_SPACE_END
#define USER_HEAP_MAX_SIZE       (USER_HEAP_END - USER_HEAP_START)

#define USER_SIGNAL_REGION_START ARCH_USER_SIGNAL_REGION_START
#define USER_SIGNAL_REGION_END   ARCH_USER_SIGNAL_REGION_END
#define USER_SIGNAL_REGION_SIZE  ARCH_USER_SIGNAL_REGION_SIZE

#endif /* _KERNEL_USER_LAYOUT_H */

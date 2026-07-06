/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_task.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose the architecture task-context type to generic scheduler code.
 * - Keep register layout details in the active architecture tree.
 *
 * Notes:
 * - task_context_t is intentionally opaque to portable kernel code at the
 *   design level, even though existing code still accesses fields directly.
 *   Those call sites are the next cleanup target.
 */

#ifndef _KERNEL_ARCH_TASK_H
#define _KERNEL_ARCH_TASK_H

#include <asm/task_context.h>

#endif /* _KERNEL_ARCH_TASK_H */

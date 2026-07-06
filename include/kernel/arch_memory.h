/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_memory.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose minimal architecture memory-context hooks to generic code.
 * - Keep MMU table symbols and CPU register vocabulary out of generic modules.
 *
 * Notes:
 * - task_context_t still stores architecture context fields today. This header
 *   is the small boundary used while the structure is made less ARM32-specific.
 */

#ifndef _KERNEL_ARCH_MEMORY_H
#define _KERNEL_ARCH_MEMORY_H

#include <kernel/types.h>

typedef uintptr_t arch_addrspace_context_t;

arch_addrspace_context_t arch_kernel_address_space_context(void);
vaddr_t arch_userfs_load_address(void);

#endif /* _KERNEL_ARCH_MEMORY_H */

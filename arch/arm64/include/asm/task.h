/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/task.h
 * Layer: ARM64 / bootstrap task lifetime
 *
 * Responsibilities:
 * - Initialize generic task_t objects with ARM64 context and stack resources.
 * - Prepare an initial high-half kernel entry and address-space identity.
 * - Carry user address spaces through the generic vm_space_t contract.
 * - Return architecture-owned stack pages when a task is destroyed.
 * - Switch cooperative generic tasks while maintaining common task state.
 *
 * Notes:
 * - The early allocator is supplied explicitly until the runtime physical
 *   allocator is available on ARM64.
 * - User address spaces are referenced but not owned by the task object.
 */

#ifndef ASM_ARM64_TASK_H
#define ASM_ARM64_TASK_H

#include <asm/task_context.h>
#include <kernel/early_page_allocator.h>

#define ARM64_BOOTSTRAP_TASK_MAX_STACK_PAGES 16u

struct task;

int arm64_task_init(struct task *task,
                    early_page_allocator_t *allocator,
                    const vm_space_t *vm_space,
                    vaddr_t kernel_entry,
                    const char *name,
                    uint32_t task_id,
                    unsigned int kernel_stack_pages);
int arm64_task_init_current(struct task *task,
                            const vm_space_t *vm_space,
                            const char *name,
                            uint32_t task_id,
                            vaddr_t kernel_stack_base,
                            vaddr_t kernel_stack_top,
                            uint32_t cpu_id);
int arm64_task_destroy(struct task *task,
                       early_page_allocator_t *allocator,
                       const arm64_task_context_t *active_context);
int arm64_task_switch(struct task *previous, struct task *next);
int arm64_task_switch_prepared(struct task *previous, struct task *next);

#endif

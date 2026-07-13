/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/task/task.c
 * Layer: ARM64 / bootstrap task lifetime
 *
 * Responsibilities:
 * - Allocate and clear task_t kernel stacks from the early page allocator.
 * - Initialize generic task metadata and ARM64 context state.
 * - Release stack ownership while protecting the active context.
 *
 * Notes:
 * - Stack pages are accessed only through the TTBR1 kernel alias.
 * - Runqueue publication and scheduling policy remain outside this backend.
 */

#include <asm/mmu.h>
#include <asm/task.h>
#include <kernel/task.h>

static void clear_bytes(void *address, size_t length)
{
    uint8_t *bytes = address;
    size_t index;

    for (index = 0; index < length; index++)
        bytes[index] = 0;
}

static void copy_task_name(char *destination, const char *name)
{
    unsigned int index = 0;

    if (!name)
        name = "arm64-task";
    while (index + 1 < TASK_NAME_MAX && name[index]) {
        destination[index] = name[index];
        index++;
    }
    destination[index] = '\0';
}

int arm64_task_init(struct task *task,
                    early_page_allocator_t *allocator,
                    const arm64_user_vm_t *user_vm,
                    vaddr_t kernel_entry,
                    const char *name,
                    uint32_t task_id,
                    unsigned int kernel_stack_pages)
{
    paddr_t stack;
    vaddr_t stack_alias;
    size_t stack_size;

    if (!task || !allocator || kernel_stack_pages == 0 ||
        kernel_stack_pages > ARM64_BOOTSTRAP_TASK_MAX_STACK_PAGES)
        return -1;
    if (task->magic == TASK_MAGIC_ALIVE)
        return -2;

    clear_bytes(task, sizeof(*task));
    if (early_page_alloc_pages(allocator, kernel_stack_pages, &stack) != 0)
        return -3;

    stack_size = (size_t)kernel_stack_pages * PAGE_SIZE;
    stack_alias = (vaddr_t)arm64_mmu_kernel_address(stack);
    if (stack_alias < ARM64_KERNEL_VA_BASE) {
        early_page_free_pages(allocator, stack, kernel_stack_pages);
        return -4;
    }
    clear_bytes((void *)(uintptr_t)stack_alias, stack_size);

    if (kernel_entry < ARM64_KERNEL_VA_BASE)
        kernel_entry = (vaddr_t)arm64_mmu_kernel_address(kernel_entry);
    if (kernel_entry < ARM64_KERNEL_VA_BASE) {
        early_page_free_pages(allocator, stack, kernel_stack_pages);
        return -5;
    }

    task->task_id = task_id;
    copy_task_name(task->name, name);
    task->state = TASK_BLOCKED;
    task->priority = TASK_DEFAULT_PRIORITY;
    task->type = TASK_TYPE_KERNEL;
    task->running_cpu = TASK_CPU_NONE;
    task->last_cpu = TASK_CPU_NONE;
    task->stack_phys_base = (void *)(uintptr_t)stack;
    task->stack_base = (void *)(uintptr_t)stack_alias;
    task->stack_size = (uint32_t)stack_size;
    task->stack_top = (void *)(uintptr_t)(stack_alias + stack_size);
    task->context.kernel.sp =
        (stack_alias + stack_size) & ~(vaddr_t)0xfu;
    task->context.kernel.pc = kernel_entry;
    task->context.user_vm = user_vm;
    if (user_vm) {
        task->context.ttbr0 = user_vm->l1;
        task->context.asid = user_vm->asid;
    }
    task->magic = TASK_MAGIC_ALIVE;
    return 0;
}

int arm64_task_destroy(struct task *task,
                       early_page_allocator_t *allocator,
                       const arm64_task_context_t *active_context)
{
    paddr_t stack;
    unsigned int stack_pages;

    if (!task || !allocator || task->magic != TASK_MAGIC_ALIVE)
        return -1;
    if (&task->context == active_context)
        return -2;

    stack = (paddr_t)(uintptr_t)task->stack_phys_base;
    if (task->stack_size == 0 || task->stack_size % PAGE_SIZE != 0)
        return -3;
    stack_pages = task->stack_size / PAGE_SIZE;
    if (stack == 0 || stack_pages == 0)
        return -3;
    if (early_page_free_pages(allocator, stack, stack_pages) != 0)
        return -4;

    clear_bytes(task, sizeof(*task));
    task->magic = TASK_MAGIC_DEAD;
    return 0;
}

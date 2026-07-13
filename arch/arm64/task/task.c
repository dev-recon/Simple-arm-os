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
 * - Attach the generic vm_space_t identity to user-capable contexts.
 * - Release stack ownership while protecting the active context.
 * - Maintain task state and CPU ownership around cooperative context switches.
 *
 * Notes:
 * - Stack pages are accessed only through the TTBR1 kernel alias.
 * - Runqueue publication and scheduling policy remain outside this backend.
 */

#include <asm/mmu.h>
#include <asm/task.h>
#include <asm/user_vm.h>
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

static void initialize_task_metadata(struct task *task,
                                     const char *name,
                                     uint32_t task_id,
                                     task_state_t state,
                                     uint32_t running_cpu)
{
    task->task_id = task_id;
    copy_task_name(task->name, name);
    task->state = state;
    task->priority = TASK_DEFAULT_PRIORITY;
    task->type = TASK_TYPE_KERNEL;
    task->running_cpu = running_cpu;
    task->last_cpu = running_cpu;
}

static int task_stack_valid(const struct task *task)
{
    vaddr_t stack_base;
    vaddr_t stack_top;

    if (!task || !task->stack_base || !task->stack_top ||
        task->stack_size == 0)
        return 0;
    stack_base = (vaddr_t)(uintptr_t)task->stack_base;
    stack_top = (vaddr_t)(uintptr_t)task->stack_top;
    return stack_base >= ARM64_KERNEL_VA_BASE &&
           stack_top == stack_base + task->stack_size;
}

int arm64_task_init(struct task *task,
                    early_page_allocator_t *allocator,
                    const vm_space_t *vm_space,
                    vaddr_t kernel_entry,
                    const char *name,
                    uint32_t task_id,
                    unsigned int kernel_stack_pages)
{
    paddr_t stack;
    vaddr_t stack_alias;
    size_t stack_size;

    if (!task || !allocator ||
        (vm_space && !arm64_user_vm_from_space(vm_space)) ||
        kernel_stack_pages == 0 ||
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

    initialize_task_metadata(task, name, task_id, TASK_BLOCKED,
                             TASK_CPU_NONE);
    task->stack_phys_base = (void *)(uintptr_t)stack;
    task->stack_base = (void *)(uintptr_t)stack_alias;
    task->stack_size = (uint32_t)stack_size;
    task->stack_top = (void *)(uintptr_t)(stack_alias + stack_size);
    task->context.kernel.sp =
        (stack_alias + stack_size) & ~(vaddr_t)0xfu;
    task->context.kernel.pc = kernel_entry;
    task->context.vm_space = vm_space;
    if (vm_space) {
        task->context.ttbr0 = (paddr_t)(uintptr_t)vm_space->pgdir;
        task->context.asid = vm_space->asid;
    }
    task->magic = TASK_MAGIC_ALIVE;
    return 0;
}

int arm64_task_init_current(struct task *task,
                            const vm_space_t *vm_space,
                            const char *name,
                            uint32_t task_id,
                            vaddr_t kernel_stack_base,
                            vaddr_t kernel_stack_top,
                            uint32_t cpu_id)
{
    if (!task || (vm_space && !arm64_user_vm_from_space(vm_space)) ||
        kernel_stack_base < ARM64_KERNEL_VA_BASE ||
        kernel_stack_top <= kernel_stack_base ||
        kernel_stack_top - kernel_stack_base > 0xffffffffULL)
        return -1;
    if (task->magic == TASK_MAGIC_ALIVE)
        return -2;

    clear_bytes(task, sizeof(*task));
    initialize_task_metadata(task, name, task_id, TASK_RUNNING, cpu_id);
    task->stack_base = (void *)(uintptr_t)kernel_stack_base;
    task->stack_top = (void *)(uintptr_t)kernel_stack_top;
    task->stack_size = (uint32_t)(kernel_stack_top - kernel_stack_base);
    task->context.vm_space = vm_space;
    if (vm_space) {
        task->context.ttbr0 = (paddr_t)(uintptr_t)vm_space->pgdir;
        task->context.asid = vm_space->asid;
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

int arm64_task_switch(struct task *previous, struct task *next)
{
    task_state_t previous_state;
    task_state_t next_state;
    uint32_t previous_cpu;
    uint32_t next_cpu;
    int result;

    if (!previous || !next || previous == next ||
        previous->magic != TASK_MAGIC_ALIVE ||
        next->magic != TASK_MAGIC_ALIVE)
        return -1;
    if (previous->state != TASK_RUNNING ||
        (next->state != TASK_BLOCKED && next->state != TASK_READY))
        return -2;
    if (!task_stack_valid(previous) || !task_stack_valid(next))
        return -3;

    previous_state = previous->state;
    next_state = next->state;
    previous_cpu = previous->running_cpu;
    next_cpu = next->running_cpu;

    previous->state = TASK_BLOCKED;
    previous->running_cpu = TASK_CPU_NONE;
    next->state = TASK_RUNNING;
    next->running_cpu = previous_cpu;
    next->last_cpu = previous_cpu;
    previous->switch_count++;

    result = arm64_task_context_switch_address_space(&previous->context,
                                                     &next->context);
    if (result != 0) {
        previous->switch_count--;
        previous->state = previous_state;
        previous->running_cpu = previous_cpu;
        next->state = next_state;
        next->running_cpu = next_cpu;
    }
    return result;
}

int arm64_task_switch_prepared(struct task *previous, struct task *next)
{
    if (!previous || !next || previous == next ||
        previous->magic != TASK_MAGIC_ALIVE ||
        next->magic != TASK_MAGIC_ALIVE)
        return -1;
    if ((previous->state != TASK_BLOCKED &&
         previous->state != TASK_READY) ||
        next->state != TASK_RUNNING ||
        previous->running_cpu != TASK_CPU_NONE ||
        next->running_cpu == TASK_CPU_NONE)
        return -2;
    if (!task_stack_valid(previous) || !task_stack_valid(next))
        return -3;
    return arm64_task_context_switch_address_space(&previous->context,
                                                    &next->context);
}

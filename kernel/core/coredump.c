/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/core/coredump.c
 * Layer: Kernel / diagnostics
 *
 * Responsibilities:
 * - Own the architecture-neutral coredump daemon lifecycle.
 * - Provide the daemon with a restricted VFS identity rooted at /tmp.
 * - Ask the active exception backend to drain captured fault records.
 *
 * Notes:
 * - Register capture and architecture page-table diagnostics remain behind
 *   arch_coredump_process_pending().
 */

#include <kernel/exceptions.h>
#include <kernel/arch_memory.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/task.h>

static task_t *coredumpd_task;

__attribute__((weak)) void arch_coredump_process_pending(void)
{
}

static void coredumpd_main(void *argument)
{
    (void)argument;

    for (;;) {
        arch_coredump_process_pending();
        task_sleep_ms(100);
    }
}

int coredumpd_start(void)
{
    process_t *vfs_context;

    if (coredumpd_task)
        return 0;
    coredumpd_task = task_create_process("coredumpd", coredumpd_main, NULL,
                                         20, TASK_TYPE_KERNEL);
    if (!coredumpd_task)
        return -1;

    vfs_context = kmalloc(sizeof(*vfs_context));
    if (!vfs_context) {
        task_destroy(coredumpd_task);
        coredumpd_task = NULL;
        return -1;
    }
    memset(vfs_context, 0, sizeof(*vfs_context));
    vfs_context->uid = 2;
    vfs_context->gid = 2;
    vfs_context->state = (proc_state_t)PROC_READY;
    strcpy(vfs_context->cwd, "/tmp");

    coredumpd_task->process = vfs_context;
    arch_task_context_set_address_space(
        &coredumpd_task->context, arch_kernel_address_space_context(),
        ASID_KERNEL);
    add_to_ready_queue(coredumpd_task);
    return 0;
}

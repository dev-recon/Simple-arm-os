/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/process/model.c
 * Layer: Kernel / generic process model
 *
 * Responsibilities:
 * - Maintain parent and child ownership through fork and reaping.
 * - Replace process VM identity atomically at the exec boundary.
 * - Publish zombie status and pending unmasked signals.
 *
 * Notes:
 * - Callers serialize mutations until the SMP process lock is introduced.
 */

#include <kernel/process_model.h>

static void clear_process(process_model_t *process)
{
    uint8_t *bytes = (uint8_t *)process;
    size_t index;

    for (index = 0; index < sizeof(*process); index++)
        bytes[index] = 0;
}

static int child_matches(const process_model_t *parent,
                         const process_model_t *child,
                         pid_t selector)
{
    if (selector == -1)
        return 1;
    if (selector > 0)
        return child->pid == selector;
    if (selector == 0)
        return child->pgid == parent->pgid;
    return child->pgid == -selector;
}

int process_model_init(process_model_t *process, pid_t pid,
                       process_model_t *parent, vm_space_t *vm_space,
                       void *task)
{
    if (!process || pid <= 0)
        return -1;
    clear_process(process);
    process->pid = pid;
    process->ppid = parent ? parent->pid : 0;
    process->pgid = parent ? parent->pgid : pid;
    process->sid = parent ? parent->sid : pid;
    process->state = PROCESS_MODEL_READY;
    process->vm_space = vm_space;
    process->task = task;
    process->parent = parent;
    if (parent) {
        process->next_sibling = parent->first_child;
        parent->first_child = process;
    }
    return 0;
}

int process_model_fork(process_model_t *parent, process_model_t *child,
                       pid_t child_pid, vm_space_t *child_vm, void *child_task)
{
    unsigned int signal;

    if (!parent || !child || parent->state == PROCESS_MODEL_ZOMBIE ||
        parent->state == PROCESS_MODEL_DEAD)
        return -1;
    if (process_model_init(child, child_pid, parent, child_vm,
                           child_task) != 0)
        return -2;
    child->blocked_signals = parent->blocked_signals;
    child->io_context = parent->io_context;
    for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
        child->signal_handlers[signal] = parent->signal_handlers[signal];
    return 0;
}

int process_model_exec(process_model_t *process, vm_space_t *new_vm)
{
    unsigned int signal;

    if (!process || !new_vm || process->state == PROCESS_MODEL_ZOMBIE ||
        process->state == PROCESS_MODEL_DEAD)
        return -1;
    process->vm_space = new_vm;
    process->pending_signals = 0;
    for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
        process->signal_handlers[signal] = 0;
    process->state = PROCESS_MODEL_READY;
    return 0;
}

int process_model_exit(process_model_t *process, int status)
{
    process_model_t *child;

    if (!process || process->state == PROCESS_MODEL_ZOMBIE ||
        process->state == PROCESS_MODEL_DEAD)
        return -1;
    process->exit_status = status;
    process->state = PROCESS_MODEL_ZOMBIE;
    child = process->first_child;
    while (child) {
        process_model_t *next = child->next_sibling;

        child->parent = NULL;
        child->ppid = 0;
        child->next_sibling = NULL;
        child = next;
    }
    process->first_child = NULL;
    return 0;
}

pid_t process_model_wait(process_model_t *parent, pid_t selector,
                         int *status, uint32_t options)
{
    process_model_t **link;
    process_model_t *child;
    int eligible = 0;

    if (!parent || (options & ~PROCESS_MODEL_WAIT_NOHANG) != 0)
        return -EINVAL;
    link = &parent->first_child;
    while (*link) {
        child = *link;
        if (!child_matches(parent, child, selector)) {
            link = &child->next_sibling;
            continue;
        }
        eligible = 1;
        if (child->state != PROCESS_MODEL_ZOMBIE) {
            link = &child->next_sibling;
            continue;
        }
        *link = child->next_sibling;
        child->next_sibling = NULL;
        child->parent = NULL;
        child->state = PROCESS_MODEL_DEAD;
        if (status)
            *status = child->exit_status;
        return child->pid;
    }
    if (!eligible)
        return -ECHILD;
    return (options & PROCESS_MODEL_WAIT_NOHANG) ? 0 : -EAGAIN;
}

int process_model_signal(process_model_t *process, unsigned int signal)
{
    if (!process || signal >= PROCESS_MODEL_SIGNAL_COUNT ||
        process->state == PROCESS_MODEL_ZOMBIE ||
        process->state == PROCESS_MODEL_DEAD)
        return -EINVAL;
    if (signal == 0)
        return 0;
    process->pending_signals |= 1u << signal;
    return 0;
}

int process_model_next_signal(process_model_t *process)
{
    uint32_t available;
    unsigned int signal;

    if (!process)
        return -EINVAL;
    available = process->pending_signals & ~process->blocked_signals;
    for (signal = 1; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++) {
        if ((available & (1u << signal)) != 0) {
            process->pending_signals &= ~(1u << signal);
            return (int)signal;
        }
    }
    return 0;
}

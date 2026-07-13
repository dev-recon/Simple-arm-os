/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/process/runtime.c
 * Layer: Kernel / process lifecycle
 *
 * Responsibilities:
 * - Apply generic fork, exec, exit and wait ordering to process_model_t.
 * - Roll back partially created children and rejected exec transitions.
 * - Coordinate scheduler publication, blocking and zombie reaping.
 *
 * Notes:
 * - Architecture backends own concrete VM and task-context mechanics.
 * - Callers serialize this first runtime until the generic process lock lands.
 */

#include <kernel/process_runtime.h>

static void clear_process(process_model_t *process)
{
    uint8_t *bytes = (uint8_t *)process;
    size_t index;

    for (index = 0; index < sizeof(*process); index++)
        bytes[index] = 0;
}

static int runtime_ops_valid(const process_runtime_ops_t *ops)
{
    return ops && ops->clone_vm && ops->destroy_vm && ops->clone_task &&
           ops->destroy_task && ops->clone_io && ops->destroy_io &&
           ops->publish_task && ops->block_current && ops->bind_task &&
           ops->validate_wait_status &&
           ops->write_wait_status && ops->replace_image;
}

int process_runtime_init(process_runtime_t *runtime,
                         const process_runtime_ops_t *ops, void *owner)
{
    if (!runtime || !runtime_ops_valid(ops))
        return -EINVAL;
    runtime->ops = *ops;
    runtime->owner = owner;
    runtime->current_process = NULL;
    runtime->current_task = NULL;
    return 0;
}

int process_runtime_select(process_runtime_t *runtime,
                           process_model_t *process, task_t *task)
{
    if (!runtime || !process || !task || process->task != task ||
        process->vm_space != task->context.vm_space)
        return -EINVAL;
    if (runtime->ops.bind_task(runtime->owner, process, task) != 0)
        return -EIO;
    runtime->current_process = process;
    runtime->current_task = task;
    return 0;
}

pid_t process_runtime_fork(process_runtime_t *runtime,
                           process_model_t *parent,
                           process_model_t *child,
                           task_t *child_task, pid_t child_pid)
{
    vm_space_t *child_vm = NULL;
    void *child_io = NULL;
    int process_created = 0;

    if (!runtime || !parent || !child || !child_task || child_pid <= 0 ||
        runtime->current_process != parent ||
        runtime->current_task != parent->task ||
        (child->state != PROCESS_MODEL_NEW &&
         child->state != PROCESS_MODEL_DEAD))
        return -EAGAIN;
    if (runtime->ops.clone_vm(runtime->owner, parent->vm_space,
                              &child_vm) != 0)
        return -ENOMEM;
    if (!child_vm || runtime->ops.clone_task(
            runtime->owner, runtime->current_task, child_task,
            child_vm) != 0)
        goto failed;
    if (runtime->ops.clone_io(runtime->owner, parent, &child_io) != 0 ||
        !child_io)
        goto failed;
    if (process_model_fork(parent, child, child_pid, child_vm,
                           child_task) != 0)
        goto failed;
    process_created = 1;
    child->io_context = child_io;
    if (runtime->ops.publish_task(runtime->owner, child_task) != 0)
        goto failed;
    return child_pid;

failed:
    if (process_created) {
        parent->first_child = child->next_sibling;
        clear_process(child);
    }
    if (child_task->magic == TASK_MAGIC_ALIVE)
        (void)runtime->ops.destroy_task(
            runtime->owner, child_task, runtime->current_task);
    if (child_io)
        (void)runtime->ops.destroy_io(runtime->owner, child_io);
    if (child_vm)
        (void)runtime->ops.destroy_vm(runtime->owner, child_vm);
    return -ENOMEM;
}

int process_runtime_exec(process_runtime_t *runtime, vm_space_t *new_vm,
                         const void *arch_image)
{
    process_model_t *process;
    vm_space_t *previous_vm;
    process_model_state_t previous_state;
    uint32_t previous_pending_signals;
    vaddr_t previous_handlers[PROCESS_MODEL_SIGNAL_COUNT];
    unsigned int signal;

    if (!runtime || !runtime->current_process || !runtime->current_task ||
        !new_vm || !arch_image)
        return -EINVAL;
    process = runtime->current_process;
    previous_vm = process->vm_space;
    previous_state = process->state;
    previous_pending_signals = process->pending_signals;
    for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
        previous_handlers[signal] = process->signal_handlers[signal];

    if (process_model_exec(process, new_vm) != 0)
        return -EINVAL;
    process->state = PROCESS_MODEL_RUNNING;
    if (runtime->ops.replace_image(
            runtime->owner, process, runtime->current_task, new_vm,
            arch_image, previous_vm) == 0)
        return 0;

    process->vm_space = previous_vm;
    process->state = previous_state;
    process->pending_signals = previous_pending_signals;
    for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
        process->signal_handlers[signal] = previous_handlers[signal];
    return -EBUSY;
}

int process_runtime_exit(process_runtime_t *runtime, int status)
{
    process_model_t *process;
    process_model_t *parent;
    task_t *parent_task;

    if (!runtime || !runtime->current_process || !runtime->current_task)
        return -ESRCH;
    process = runtime->current_process;
    parent = process->parent;
    if (process_model_exit(process, status) != 0)
        return -EINVAL;
    if (!parent || !parent->task)
        return 0;
    parent_task = (task_t *)parent->task;
    if (parent_task->state == TASK_BLOCKED &&
        runtime->ops.publish_task(runtime->owner, parent_task) != 0)
        return -EAGAIN;
    return 0;
}

pid_t process_runtime_wait(process_runtime_t *runtime,
                           process_model_t *parent,
                           process_model_t *child,
                           pid_t selector, vaddr_t status_address,
                           uint32_t options)
{
    vm_space_t *child_vm;
    task_t *child_task;
    pid_t result;
    int status;

    if (!runtime || !parent || !child ||
        runtime->current_process != parent ||
        runtime->current_task != parent->task)
        return -ESRCH;
    if (status_address != 0 && runtime->ops.validate_wait_status(
            runtime->owner, parent->vm_space, status_address) != 0)
        return -EFAULT;

    result = process_model_wait(parent, selector, &status, options);
    if (result == -EAGAIN &&
        (options & PROCESS_MODEL_WAIT_NOHANG) == 0) {
        if (runtime->ops.block_current(runtime->owner) != 0)
            return -EAGAIN;
        result = process_model_wait(parent, selector, &status, 0);
    }
    if (result <= 0)
        return result;
    if (child->pid != result || !child->task || !child->vm_space)
        return -ECHILD;
    if (status_address != 0 && runtime->ops.write_wait_status(
            runtime->owner, status_address, status << 8) != 0)
        return -EFAULT;

    child_task = (task_t *)child->task;
    child_vm = child->vm_space;
    if (runtime->ops.destroy_task(
            runtime->owner, child_task, runtime->current_task) != 0 ||
        runtime->ops.destroy_vm(runtime->owner, child_vm) != 0 ||
        runtime->ops.destroy_io(runtime->owner,
                                child->io_context) != 0)
        return -EIO;
    return result;
}

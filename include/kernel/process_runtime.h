/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/process_runtime.h
 * Layer: Kernel / process lifecycle
 *
 * Responsibilities:
 * - Orchestrate fork, exec, exit and wait above the generic process model.
 * - Keep parent/child state, scheduler blocking and resource rollback ordered.
 * - Delegate VM, task-context and user-copy mechanics to architecture backends.
 *
 * Notes:
 * - Storage policy remains with the caller; the runtime accepts explicit
 *   process and task objects so early bootstrap and the full kernel can share
 *   the same lifecycle rules.
 */

#ifndef _KERNEL_PROCESS_RUNTIME_H
#define _KERNEL_PROCESS_RUNTIME_H

#include <kernel/process_model.h>
#include <kernel/task.h>

typedef struct process_runtime_ops {
    int (*clone_vm)(void *owner, const vm_space_t *source,
                    vm_space_t **destination);
    int (*destroy_vm)(void *owner, vm_space_t *vm_space);
    int (*clone_task)(void *owner, const task_t *parent, task_t *child,
                      vm_space_t *child_vm);
    int (*destroy_task)(void *owner, task_t *task,
                        const task_t *active_task);
    int (*clone_io)(void *owner, const process_model_t *parent,
                    void **child_io);
    int (*destroy_io)(void *owner, void *io_context);
    int (*publish_task)(void *owner, task_t *task);
    int (*block_current)(void *owner);
    int (*bind_task)(void *owner, process_model_t *process, task_t *task);
    int (*validate_wait_status)(void *owner, const vm_space_t *vm_space,
                                vaddr_t address);
    int (*write_wait_status)(void *owner, vaddr_t address, int status);
    int (*replace_image)(void *owner, process_model_t *process, task_t *task,
                         vm_space_t *new_vm, const void *arch_image,
                         vm_space_t *previous_vm);
} process_runtime_ops_t;

typedef struct process_runtime {
    process_runtime_ops_t ops;
    void *owner;
    process_model_t *current_process;
    task_t *current_task;
} process_runtime_t;

int process_runtime_init(process_runtime_t *runtime,
                         const process_runtime_ops_t *ops, void *owner);
int process_runtime_select(process_runtime_t *runtime,
                           process_model_t *process, task_t *task);
pid_t process_runtime_fork(process_runtime_t *runtime,
                           process_model_t *parent,
                           process_model_t *child,
                           task_t *child_task, pid_t child_pid);
int process_runtime_exec(process_runtime_t *runtime, vm_space_t *new_vm,
                         const void *arch_image);
int process_runtime_exit(process_runtime_t *runtime, int status);
pid_t process_runtime_wait(process_runtime_t *runtime,
                           process_model_t *parent,
                           process_model_t *child,
                           pid_t selector, vaddr_t status_address,
                           uint32_t options);

int process_runtime_clone_process(process_t *child, const process_t *parent,
                                  vm_space_t *child_vm, pid_t child_pid);
void process_runtime_release_process(process_t *process);

#endif /* _KERNEL_PROCESS_RUNTIME_H */

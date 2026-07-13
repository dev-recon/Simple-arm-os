/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/process_model.h
 * Layer: Kernel / generic process model
 *
 * Responsibilities:
 * - Define architecture-neutral parent, child and zombie relationships.
 * - Model fork, exec, wait and signal state without VFS dependencies.
 * - Keep task and VM ownership explicit at the process boundary.
 *
 * Notes:
 * - Concrete schedulers own task allocation and blocking.
 * - Concrete exec backends own image acquisition and VM construction.
 */

#ifndef _KERNEL_PROCESS_MODEL_H
#define _KERNEL_PROCESS_MODEL_H

#include <kernel/memory.h>
#include <kernel/types.h>

#define PROCESS_MODEL_SIGNAL_COUNT 32u
#define PROCESS_MODEL_WAIT_NOHANG  1u
#define PROCESS_MODEL_WAIT_UNTRACED 2u

typedef enum process_model_state {
    PROCESS_MODEL_NEW = 0,
    PROCESS_MODEL_READY,
    PROCESS_MODEL_RUNNING,
    PROCESS_MODEL_BLOCKED,
    PROCESS_MODEL_STOPPED,
    PROCESS_MODEL_ZOMBIE,
    PROCESS_MODEL_DEAD
} process_model_state_t;

typedef struct process_model {
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    pid_t sid;
    process_model_state_t state;
    int exit_status;
    uint32_t pending_signals;
    uint32_t blocked_signals;
    vaddr_t signal_handlers[PROCESS_MODEL_SIGNAL_COUNT];
    vm_space_t *vm_space;
    void *task;
    void *io_context;
    struct process_model *parent;
    struct process_model *first_child;
    struct process_model *next_sibling;
} process_model_t;

int process_model_init(process_model_t *process, pid_t pid,
                       process_model_t *parent, vm_space_t *vm_space,
                       void *task);
int process_model_fork(process_model_t *parent, process_model_t *child,
                       pid_t child_pid, vm_space_t *child_vm, void *child_task);
int process_model_exec(process_model_t *process, vm_space_t *new_vm);
int process_model_exit(process_model_t *process, int status);
pid_t process_model_wait(process_model_t *parent, pid_t selector,
                         int *status, uint32_t options);
int process_model_signal(process_model_t *process, unsigned int signal);
int process_model_next_signal(process_model_t *process);

#endif /* _KERNEL_PROCESS_MODEL_H */

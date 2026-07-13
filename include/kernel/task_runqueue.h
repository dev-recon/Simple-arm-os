/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/task_runqueue.h
 * Layer: Kernel / cooperative scheduling
 *
 * Responsibilities:
 * - Define a bounded intrusive FIFO runqueue for generic task_t objects.
 * - Publish blocked tasks as ready and select ready tasks cooperatively.
 * - Drive voluntary, blocking, and timer-preemption reschedules.
 * - Coalesce timer requests and service them only at declared safe points.
 * - Account timer slices and request preemption at quantum expiration.
 * - Validate queue links, task lifetime guards, and membership accounting.
 *
 * Notes:
 * - This first reusable queue is single-CPU and intentionally lockless.
 * - Yield may run from a kernel task or from a syscall after saving EL0 state.
 * - Timer ticks enter with local IRQs masked; other dispatcher mutations use
 *   the configured architecture callbacks.
 * - Preemption is deferred to an architecture-safe IRQ return point.
 * - Priority selection and SMP synchronization remain separate.
 */

#ifndef _KERNEL_TASK_RUNQUEUE_H
#define _KERNEL_TASK_RUNQUEUE_H

#include <kernel/task.h>

typedef struct task_runqueue {
    task_t *head;
    task_t *tail;
    uint32_t count;
    uint32_t capacity;
} task_runqueue_t;

typedef enum task_dispatch_reason {
    TASK_DISPATCH_NONE = 0,
    TASK_DISPATCH_YIELD,
    TASK_DISPATCH_PREEMPT,
    TASK_DISPATCH_BLOCK
} task_dispatch_reason_t;

typedef int (*task_dispatch_switch_t)(task_t *previous, task_t *next);
typedef uint32_t (*task_dispatch_irq_save_t)(void *context);
typedef void (*task_dispatch_irq_restore_t)(void *context,
                                            uint32_t saved_state);

typedef struct task_dispatcher {
    task_runqueue_t ready;
    task_t *current;
    task_dispatch_switch_t switch_task;
    task_dispatch_irq_save_t irq_save;
    task_dispatch_irq_restore_t irq_restore;
    void *irq_context;
    uint64_t dispatch_count;
    uint64_t preempt_requests;
    uint64_t preempt_deferred;
    uint64_t preempt_serviced;
    uint64_t timer_ticks;
    uint64_t quantum_expirations;
    uint64_t irq_critical_sections;
    task_dispatch_reason_t last_reason;
    volatile uint32_t need_resched;
    uint32_t preempt_disable_depth;
    uint32_t quantum_ticks;
    uint32_t slice_ticks;
} task_dispatcher_t;

int task_runqueue_init(task_runqueue_t *queue, uint32_t capacity);
int task_runqueue_publish(task_runqueue_t *queue, task_t *task);
task_t *task_runqueue_take(task_runqueue_t *queue);
int task_runqueue_validate(const task_runqueue_t *queue);

int task_dispatcher_init(task_dispatcher_t *dispatcher,
                         task_t *current,
                         uint32_t capacity,
                         task_dispatch_switch_t switch_task);
int task_dispatcher_publish(task_dispatcher_t *dispatcher, task_t *task);
int task_dispatcher_set_irq_ops(task_dispatcher_t *dispatcher,
                                task_dispatch_irq_save_t irq_save,
                                task_dispatch_irq_restore_t irq_restore,
                                void *irq_context);
int task_dispatcher_yield(task_dispatcher_t *dispatcher);
int task_dispatcher_set_quantum(task_dispatcher_t *dispatcher,
                                uint32_t quantum_ticks);
int task_dispatcher_timer_tick(task_dispatcher_t *dispatcher);
int task_dispatcher_request_preempt(task_dispatcher_t *dispatcher);
int task_dispatcher_preempt_disable(task_dispatcher_t *dispatcher);
int task_dispatcher_preempt_enable(task_dispatcher_t *dispatcher);
int task_dispatcher_service_preempt_at_safe_point(
    task_dispatcher_t *dispatcher);
int task_dispatcher_block(task_dispatcher_t *dispatcher);
int task_dispatcher_validate(const task_dispatcher_t *dispatcher);

#endif /* _KERNEL_TASK_RUNQUEUE_H */

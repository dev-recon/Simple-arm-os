/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/task/runqueue.c
 * Layer: Kernel / cooperative scheduling
 *
 * Responsibilities:
 * - Maintain a bounded intrusive FIFO of ready generic tasks.
 * - Reject duplicate, lifetime-state, and capacity violations before
 *   publication.
 * - Detach selected tasks without changing architecture context state.
 * - Coordinate cooperative dispatch and deferred timer preemption.
 *
 * Notes:
 * - The caller performs the architecture switch after taking a ready task.
 * - Locking is omitted until the ARM64 SMP scheduler milestone.
 */

#include <kernel/task_runqueue.h>

int task_runqueue_validate(const task_runqueue_t *queue)
{
    const task_t *previous = NULL;
    const task_t *task;
    uint32_t count = 0;

    if (!queue || queue->capacity == 0 || queue->capacity > MAX_TASKS ||
        queue->count > queue->capacity)
        return -1;
    if ((queue->head == NULL) != (queue->tail == NULL))
        return -2;

    task = queue->head;
    while (task) {
        if (count >= queue->capacity ||
            task->magic != TASK_MAGIC_ALIVE ||
            task->state != TASK_READY ||
            task->priority >= TASK_PRIORITY_LEVELS ||
            task->rq_prev != previous ||
            task->rq_priority != task->priority)
            return -3;
        previous = task;
        task = task->rq_next;
        count++;
    }
    if (count != queue->count || previous != queue->tail)
        return -4;
    if (queue->head && queue->head->rq_prev != NULL)
        return -5;
    if (queue->tail && queue->tail->rq_next != NULL)
        return -6;
    return 0;
}

int task_runqueue_init(task_runqueue_t *queue, uint32_t capacity)
{
    if (!queue || capacity == 0 || capacity > MAX_TASKS)
        return -1;
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;
    queue->capacity = capacity;
    return 0;
}

int task_runqueue_publish(task_runqueue_t *queue, task_t *task)
{
    if (task_runqueue_validate(queue) != 0 || !task ||
        task->magic != TASK_MAGIC_ALIVE || task->state != TASK_BLOCKED ||
        task->priority >= TASK_PRIORITY_LEVELS ||
        task->rq_next != NULL || task->rq_prev != NULL ||
        queue->count >= queue->capacity)
        return -1;

    task->state = TASK_READY;
    task->rq_priority = task->priority;
    task->rq_prev = queue->tail;
    task->rq_next = NULL;
    if (queue->tail)
        queue->tail->rq_next = task;
    else
        queue->head = task;
    queue->tail = task;
    queue->count++;

    if (task_runqueue_validate(queue) != 0)
        return -2;
    return 0;
}

task_t *task_runqueue_take(task_runqueue_t *queue)
{
    task_t *task;

    if (task_runqueue_validate(queue) != 0 || queue->count == 0)
        return NULL;

    task = queue->head;
    queue->head = task->rq_next;
    if (queue->head)
        queue->head->rq_prev = NULL;
    else
        queue->tail = NULL;
    queue->count--;

    task->rq_next = NULL;
    task->rq_prev = NULL;
    task->rq_priority = TASK_PRIORITY_LEVELS;
    if (task_runqueue_validate(queue) != 0)
        return NULL;
    return task;
}

static void runqueue_attach_front(task_runqueue_t *queue, task_t *task)
{
    task->state = TASK_READY;
    task->rq_priority = task->priority;
    task->rq_prev = NULL;
    task->rq_next = queue->head;
    if (queue->head)
        queue->head->rq_prev = task;
    else
        queue->tail = task;
    queue->head = task;
    queue->count++;
}

static void runqueue_detach(task_runqueue_t *queue, task_t *task)
{
    if (task->rq_prev)
        task->rq_prev->rq_next = task->rq_next;
    else
        queue->head = task->rq_next;
    if (task->rq_next)
        task->rq_next->rq_prev = task->rq_prev;
    else
        queue->tail = task->rq_prev;
    queue->count--;
    task->rq_next = NULL;
    task->rq_prev = NULL;
    task->rq_priority = TASK_PRIORITY_LEVELS;
}

int task_dispatcher_validate(const task_dispatcher_t *dispatcher)
{
    if (!dispatcher || !dispatcher->current || !dispatcher->switch_task ||
        dispatcher->current->magic != TASK_MAGIC_ALIVE ||
        dispatcher->current->state != TASK_RUNNING ||
        dispatcher->current->running_cpu == TASK_CPU_NONE ||
        task_runqueue_validate(&dispatcher->ready) != 0)
        return -1;
    return 0;
}

int task_dispatcher_init(task_dispatcher_t *dispatcher,
                         task_t *current,
                         uint32_t capacity,
                         task_dispatch_switch_t switch_task)
{
    if (!dispatcher || !current || !switch_task ||
        current->magic != TASK_MAGIC_ALIVE ||
        current->state != TASK_RUNNING ||
        current->running_cpu == TASK_CPU_NONE)
        return -1;
    if (task_runqueue_init(&dispatcher->ready, capacity) != 0)
        return -2;
    dispatcher->current = current;
    dispatcher->switch_task = switch_task;
    dispatcher->dispatch_count = 0;
    dispatcher->preempt_requests = 0;
    dispatcher->preempt_deferred = 0;
    dispatcher->preempt_serviced = 0;
    dispatcher->last_reason = TASK_DISPATCH_NONE;
    dispatcher->need_resched = 0;
    dispatcher->preempt_disable_depth = 0;
    return 0;
}

int task_dispatcher_publish(task_dispatcher_t *dispatcher, task_t *task)
{
    if (task_dispatcher_validate(dispatcher) != 0)
        return -1;
    return task_runqueue_publish(&dispatcher->ready, task);
}

static int task_dispatcher_reschedule(task_dispatcher_t *dispatcher,
                                      task_dispatch_reason_t reason)
{
    task_t *previous;
    task_t *next;
    uint32_t previous_cpu;
    uint32_t previous_last_cpu;
    uint32_t next_cpu;
    uint32_t next_last_cpu;
    task_dispatch_reason_t last_reason;
    int requeue;
    int result;

    if (task_dispatcher_validate(dispatcher) != 0 ||
        reason <= TASK_DISPATCH_NONE || reason > TASK_DISPATCH_BLOCK)
        return -1;
    requeue = reason != TASK_DISPATCH_BLOCK;
    if (dispatcher->ready.count == 0)
        return requeue ? 0 : -2;

    previous = dispatcher->current;
    previous_cpu = previous->running_cpu;
    previous_last_cpu = previous->last_cpu;
    last_reason = dispatcher->last_reason;
    next = task_runqueue_take(&dispatcher->ready);
    if (!next)
        return -3;
    next_cpu = next->running_cpu;
    next_last_cpu = next->last_cpu;

    previous->state = TASK_BLOCKED;
    previous->running_cpu = TASK_CPU_NONE;
    if (requeue && task_runqueue_publish(&dispatcher->ready, previous) != 0) {
        previous->state = TASK_RUNNING;
        previous->running_cpu = previous_cpu;
        runqueue_attach_front(&dispatcher->ready, next);
        return -4;
    }

    next->state = TASK_RUNNING;
    next->running_cpu = previous_cpu;
    next->last_cpu = previous_cpu;
    previous->switch_count++;
    dispatcher->current = next;
    dispatcher->dispatch_count++;
    dispatcher->last_reason = reason;

    result = dispatcher->switch_task(previous, next);
    if (result != 0) {
        if (requeue)
            runqueue_detach(&dispatcher->ready, previous);
        previous->state = TASK_RUNNING;
        previous->running_cpu = previous_cpu;
        previous->last_cpu = previous_last_cpu;
        previous->switch_count--;
        next->state = TASK_READY;
        next->running_cpu = next_cpu;
        next->last_cpu = next_last_cpu;
        runqueue_attach_front(&dispatcher->ready, next);
        dispatcher->current = previous;
        dispatcher->dispatch_count--;
        dispatcher->last_reason = last_reason;
        return result;
    }
    return 0;
}

int task_dispatcher_yield(task_dispatcher_t *dispatcher)
{
    return task_dispatcher_reschedule(dispatcher, TASK_DISPATCH_YIELD);
}

int task_dispatcher_request_preempt(task_dispatcher_t *dispatcher)
{
    if (!dispatcher || !dispatcher->current || !dispatcher->switch_task)
        return -1;
    dispatcher->need_resched = 1;
    dispatcher->preempt_requests++;
    return 0;
}

int task_dispatcher_preempt_disable(task_dispatcher_t *dispatcher)
{
    if (task_dispatcher_validate(dispatcher) != 0 ||
        dispatcher->preempt_disable_depth == 0xffffffffu)
        return -1;
    dispatcher->preempt_disable_depth++;
    return 0;
}

int task_dispatcher_preempt_enable(task_dispatcher_t *dispatcher)
{
    if (task_dispatcher_validate(dispatcher) != 0 ||
        dispatcher->preempt_disable_depth == 0)
        return -1;
    dispatcher->preempt_disable_depth--;
    return dispatcher->need_resched != 0;
}

int task_dispatcher_service_preempt_at_safe_point(
    task_dispatcher_t *dispatcher)
{
    int result;

    if (task_dispatcher_validate(dispatcher) != 0)
        return -1;
    if (dispatcher->need_resched == 0)
        return 0;
    if (dispatcher->preempt_disable_depth != 0 ||
        dispatcher->ready.count == 0) {
        dispatcher->preempt_deferred++;
        return 0;
    }

    dispatcher->need_resched = 0;
    result = task_dispatcher_reschedule(dispatcher, TASK_DISPATCH_PREEMPT);
    if (result != 0) {
        dispatcher->need_resched = 1;
        return result;
    }
    dispatcher->preempt_serviced++;
    return 0;
}

int task_dispatcher_block(task_dispatcher_t *dispatcher)
{
    return task_dispatcher_reschedule(dispatcher, TASK_DISPATCH_BLOCK);
}

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
 * - Account timer ticks and request scheduling only at quantum expiration.
 * - Mask local IRQs around externally visible runqueue mutations.
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
    uint32_t sleeping_count = 0;
    unsigned int index;

    if (!dispatcher || !dispatcher->current || !dispatcher->switch_task ||
        dispatcher->current->magic != TASK_MAGIC_ALIVE ||
        dispatcher->current->state != TASK_RUNNING ||
        dispatcher->current->running_cpu == TASK_CPU_NONE ||
        dispatcher->quantum_ticks == 0 ||
        dispatcher->slice_ticks >= dispatcher->quantum_ticks ||
        ((dispatcher->irq_save == NULL) !=
         (dispatcher->irq_restore == NULL)) ||
        task_runqueue_validate(&dispatcher->ready) != 0)
        return -1;
    for (index = 0; index < TASK_DISPATCHER_MAX_SLEEPERS; index++) {
        task_t *task = dispatcher->sleeping[index];
        unsigned int previous;

        if (!task)
            continue;
        if (task->magic != TASK_MAGIC_ALIVE || task->wakeup_time == 0 ||
            (task->state != TASK_BLOCKED &&
             !(task == dispatcher->current &&
               task->state == TASK_RUNNING)))
            return -1;
        for (previous = 0; previous < index; previous++) {
            if (dispatcher->sleeping[previous] == task)
                return -1;
        }
        sleeping_count++;
    }
    if (sleeping_count != dispatcher->sleeping_count)
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
    for (capacity = 0; capacity < TASK_DISPATCHER_MAX_SLEEPERS;
         capacity++)
        dispatcher->sleeping[capacity] = NULL;
    dispatcher->sleeping_count = 0;
    dispatcher->current = current;
    dispatcher->switch_task = switch_task;
    dispatcher->irq_save = NULL;
    dispatcher->irq_restore = NULL;
    dispatcher->irq_context = NULL;
    dispatcher->dispatch_count = 0;
    dispatcher->preempt_requests = 0;
    dispatcher->preempt_deferred = 0;
    dispatcher->preempt_serviced = 0;
    dispatcher->timer_ticks = 0;
    dispatcher->quantum_expirations = 0;
    dispatcher->irq_critical_sections = 0;
    dispatcher->last_reason = TASK_DISPATCH_NONE;
    dispatcher->need_resched = 0;
    dispatcher->preempt_disable_depth = 0;
    dispatcher->quantum_ticks = 1;
    dispatcher->slice_ticks = 0;
    return 0;
}

static uint32_t task_dispatcher_critical_enter(
    task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = 0;

    if (dispatcher && dispatcher->irq_save) {
        saved_state = dispatcher->irq_save(dispatcher->irq_context);
        dispatcher->irq_critical_sections++;
    }
    return saved_state;
}

static void task_dispatcher_critical_leave(
    task_dispatcher_t *dispatcher,
    uint32_t saved_state)
{
    if (dispatcher && dispatcher->irq_restore)
        dispatcher->irq_restore(dispatcher->irq_context, saved_state);
}

int task_dispatcher_set_irq_ops(task_dispatcher_t *dispatcher,
                                task_dispatch_irq_save_t irq_save,
                                task_dispatch_irq_restore_t irq_restore,
                                void *irq_context)
{
    if (task_dispatcher_validate(dispatcher) != 0 || !irq_save ||
        !irq_restore || dispatcher->irq_save || dispatcher->irq_restore)
        return -1;
    dispatcher->irq_save = irq_save;
    dispatcher->irq_restore = irq_restore;
    dispatcher->irq_context = irq_context;
    return 0;
}

int task_dispatcher_publish(task_dispatcher_t *dispatcher, task_t *task)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result;

    if (task_dispatcher_validate(dispatcher) != 0)
        result = -1;
    else
        result = task_runqueue_publish(&dispatcher->ready, task);
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
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
    uint32_t previous_slice_ticks;
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
    previous_slice_ticks = dispatcher->slice_ticks;
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
    dispatcher->slice_ticks = 0;

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
        dispatcher->slice_ticks = previous_slice_ticks;
        return result;
    }
    return 0;
}

int task_dispatcher_yield(task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result = task_dispatcher_reschedule(dispatcher,
                                            TASK_DISPATCH_YIELD);

    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_set_quantum(task_dispatcher_t *dispatcher,
                                uint32_t quantum_ticks)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result = 0;

    if (task_dispatcher_validate(dispatcher) != 0 || quantum_ticks == 0)
        result = -1;
    else {
        dispatcher->quantum_ticks = quantum_ticks;
        dispatcher->slice_ticks = 0;
    }
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

static int task_dispatcher_request_preempt_locked(
    task_dispatcher_t *dispatcher)
{
    if (!dispatcher || !dispatcher->current || !dispatcher->switch_task)
        return -1;
    dispatcher->need_resched = 1;
    dispatcher->preempt_requests++;
    return 0;
}

int task_dispatcher_timer_tick(task_dispatcher_t *dispatcher)
{
    unsigned int index;

    if (task_dispatcher_validate(dispatcher) != 0 ||
        dispatcher->quantum_ticks == 0)
        return -1;

    for (index = 0; index < TASK_DISPATCHER_MAX_SLEEPERS; index++) {
        task_t *task = dispatcher->sleeping[index];

        if (!task ||
            (int32_t)((uint32_t)dispatcher->timer_ticks -
                      task->wakeup_time) < 0)
            continue;
        dispatcher->sleeping[index] = NULL;
        dispatcher->sleeping_count--;
        task->wakeup_time = 0;
        if (task_runqueue_publish(&dispatcher->ready, task) != 0)
            return -1;
    }

    dispatcher->timer_ticks++;
    dispatcher->slice_ticks++;
    if (dispatcher->slice_ticks < dispatcher->quantum_ticks)
        return 0;

    dispatcher->slice_ticks = 0;
    dispatcher->quantum_expirations++;
    return task_dispatcher_request_preempt_locked(dispatcher);
}

int task_dispatcher_sleep_until(task_dispatcher_t *dispatcher,
                                uint32_t wake_tick)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    task_t *current;
    unsigned int slot;
    int result;

    if (task_dispatcher_validate(dispatcher) != 0 || wake_tick == 0 ||
        dispatcher->sleeping_count >= TASK_DISPATCHER_MAX_SLEEPERS) {
        result = -1;
        goto out;
    }
    for (slot = 0; slot < TASK_DISPATCHER_MAX_SLEEPERS; slot++) {
        if (!dispatcher->sleeping[slot])
            break;
    }
    if (slot == TASK_DISPATCHER_MAX_SLEEPERS) {
        result = -1;
        goto out;
    }

    current = dispatcher->current;
    current->wakeup_time = wake_tick;
    dispatcher->sleeping[slot] = current;
    dispatcher->sleeping_count++;
    result = task_dispatcher_reschedule(dispatcher, TASK_DISPATCH_BLOCK);
    if (result != 0) {
        dispatcher->sleeping[slot] = NULL;
        dispatcher->sleeping_count--;
        current->wakeup_time = 0;
    }
out:
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_request_preempt(task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result = task_dispatcher_request_preempt_locked(dispatcher);

    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_preempt_disable(task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result = 0;

    if (task_dispatcher_validate(dispatcher) != 0 ||
        dispatcher->preempt_disable_depth == 0xffffffffu)
        result = -1;
    else
        dispatcher->preempt_disable_depth++;
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_preempt_enable(task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result;

    if (task_dispatcher_validate(dispatcher) != 0 ||
        dispatcher->preempt_disable_depth == 0)
        result = -1;
    else {
        dispatcher->preempt_disable_depth--;
        result = dispatcher->need_resched != 0;
    }
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_service_preempt_at_safe_point(
    task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result;

    if (task_dispatcher_validate(dispatcher) != 0) {
        result = -1;
        goto out;
    }
    if (dispatcher->need_resched == 0) {
        result = 0;
        goto out;
    }
    if (dispatcher->preempt_disable_depth != 0 ||
        dispatcher->ready.count == 0) {
        dispatcher->preempt_deferred++;
        result = 0;
        goto out;
    }

    dispatcher->need_resched = 0;
    result = task_dispatcher_reschedule(dispatcher, TASK_DISPATCH_PREEMPT);
    if (result != 0) {
        dispatcher->need_resched = 1;
        goto out;
    }
    dispatcher->preempt_serviced++;
out:
    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

int task_dispatcher_block(task_dispatcher_t *dispatcher)
{
    uint32_t saved_state = task_dispatcher_critical_enter(dispatcher);
    int result = task_dispatcher_reschedule(dispatcher,
                                            TASK_DISPATCH_BLOCK);

    task_dispatcher_critical_leave(dispatcher, saved_state);
    return result;
}

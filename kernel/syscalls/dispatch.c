/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/syscalls/dispatch.c
 * Layer: Kernel / generic syscall dispatch
 *
 * Responsibilities:
 * - Initialize and validate the complete ArmOS syscall-number table.
 * - Register subsystem handlers without architecture-specific casts.
 * - Dispatch native-width requests and account rejected calls.
 *
 * Notes:
 * - Synchronization is supplied by the owning scheduler when SMP arrives.
 */

#include <kernel/syscall_dispatch.h>

static void clear_dispatcher(syscall_dispatcher_t *dispatcher)
{
    uint8_t *bytes = (uint8_t *)dispatcher;
    size_t index;

    for (index = 0; index < sizeof(*dispatcher); index++)
        bytes[index] = 0;
}

void syscall_dispatcher_init(syscall_dispatcher_t *dispatcher)
{
    if (dispatcher)
        clear_dispatcher(dispatcher);
}

int syscall_dispatcher_register(syscall_dispatcher_t *dispatcher,
                                uint32_t number,
                                syscall_dispatch_handler_t handler,
                                void *owner)
{
    if (!dispatcher || !handler || number >= ARMOS_SYSCALL_MAX ||
        dispatcher->handlers[number] != NULL)
        return -1;
    dispatcher->handlers[number] = handler;
    dispatcher->owners[number] = owner;
    return 0;
}

int syscall_dispatcher_bind(syscall_dispatcher_t *dispatcher,
                            uint32_t number,
                            syscall_dispatch_handler_t handler,
                            void *owner)
{
    if (!dispatcher || !handler || number >= ARMOS_SYSCALL_MAX)
        return -1;
    dispatcher->handlers[number] = handler;
    dispatcher->owners[number] = owner;
    return 0;
}

int syscall_dispatcher_set_fallback(syscall_dispatcher_t *dispatcher,
                                    syscall_dispatch_handler_t handler,
                                    void *owner)
{
    if (!dispatcher || !handler || dispatcher->fallback)
        return -1;
    dispatcher->fallback = handler;
    dispatcher->fallback_owner = owner;
    return 0;
}

syscall_result_t syscall_dispatcher_dispatch(
    syscall_dispatcher_t *dispatcher,
    const syscall_request_t *request)
{
    syscall_dispatch_handler_t handler;

    if (!dispatcher || !request || request->number >= ARMOS_SYSCALL_MAX) {
        if (dispatcher)
            dispatcher->rejected++;
        return -(syscall_result_t)ENOSYS;
    }
    handler = dispatcher->handlers[request->number];
    if (!handler) {
        handler = dispatcher->fallback;
        if (!handler) {
            dispatcher->rejected++;
            return -(syscall_result_t)ENOSYS;
        }
        dispatcher->calls++;
        return handler(dispatcher->fallback_owner, request);
    }
    dispatcher->calls++;
    return handler(dispatcher->owners[request->number], request);
}

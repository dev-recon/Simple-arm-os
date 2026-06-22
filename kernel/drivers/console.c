/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/console.c
 * Layer: Kernel / terminal and character devices
 *
 * Responsibilities:
 * - Drive UART/framebuffer console backends and TTY line discipline.
 * - Preserve canonical/raw terminal semantics and job-control signals.
 *
 * Notes:
 * - tty0/UART must remain a reliable fallback path.
 */

#include <kernel/vfs.h>
#include <kernel/display.h>
#include <kernel/keyboard.h>
#include <kernel/kernel.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

/* Console device operations */
ssize_t console_device_read(file_t* file, void* buffer, size_t count)
{
    char* buf = (char*)buffer;
    size_t bytes_read = 0;
    char c;
    
    /* Suppression du warning unused parameter */
    (void)file;
    
    while (bytes_read < count) {
        c = keyboard_getchar();
        if (c == (char)-1) {
            /* Interrupted by signal */
            return bytes_read > 0 ? (ssize_t)bytes_read : (ssize_t)-EINTR;
        }
        
        /* Echo character */
        if (c == '\r') c = '\n';
        console_putchar(c);
        
        buf[bytes_read++] = c;
        
        /* Stop on newline for line buffering */
        if (c == '\n') break;
    }
    
    return (ssize_t)bytes_read;
}

ssize_t console_device_write(file_t* file, const void* buffer, size_t count)
{
    return framebuffer_write(file, buffer, count);
}

void init_console_devices(void)
{
    /* Register console devices */
    /* This would be implemented when we have device registration */
    KINFO("Console devices initialized\n");
}

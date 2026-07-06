/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/uart.h
 * Layer: Kernel / terminal and character devices
 *
 * Responsibilities:
 * - Drive UART/framebuffer console backends and TTY line discipline.
 * - Preserve canonical/raw terminal semantics and job-control signals.
 *
 * Notes:
 * - tty0/UART must remain a reliable fallback path.
 */

#ifndef UART_H
#define UART_H

#include <kernel/task.h>

void uart_init(void);
void uart_attach_tty_backend(void);
void uart_use_kernel_mmio_alias(void);
void uart_putc(char c);
bool uart_try_putc(char c);
bool uart_tx_ready(void);
void uart_puts(const char* str);
int uart_getc(void);
bool uart_has_data(void);
void uart_set_tx_irq_enabled(bool enabled);
void uart_put_hex(unsigned long value);
void uart_put_dec(int num);
void uart_irq_handler(void);

file_t* create_uart_console_file(const char* name, int flags);

#endif // UART_H

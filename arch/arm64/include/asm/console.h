/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/console.h
 * Layer: ARM64 / platform console
 *
 * Responsibilities:
 * - Declare polling input plus diagnostic output for the platform UART.
 * - Keep ARM64 bootstrap and exception output independent from libc.
 *
 * Notes:
 * - Implementations remain available before and after MMU activation.
 */

#ifndef ARMOS_ARM64_CONSOLE_H
#define ARMOS_ARM64_CONSOLE_H

typedef unsigned long long arm64_console_u64;

void arm64_console_putc(char c);
void arm64_console_puts(const char *text);
void arm64_console_puthex64(arm64_console_u64 value);
int arm64_console_try_getc(char *character);
char arm64_console_getc(void);

#endif /* ARMOS_ARM64_CONSOLE_H */

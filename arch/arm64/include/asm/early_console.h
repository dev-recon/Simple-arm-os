/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/early_console.h
 * Layer: ARM64 / early platform diagnostics
 *
 * Responsibilities:
 * - Declare character, string and hexadecimal output before the TTY exists.
 * - Keep early ARM64 diagnostics independent from libc and formatted I/O.
 *
 * Notes:
 * - Implementations are platform-specific and must remain available during
 *   exception and MMU bring-up.
 */

#ifndef ARMOS_ARM64_EARLY_CONSOLE_H
#define ARMOS_ARM64_EARLY_CONSOLE_H

typedef unsigned long long arm64_early_u64;

void arm64_early_putc(char c);
void arm64_early_puts(const char *text);
void arm64_early_puthex64(arm64_early_u64 value);

#endif /* ARMOS_ARM64_EARLY_CONSOLE_H */

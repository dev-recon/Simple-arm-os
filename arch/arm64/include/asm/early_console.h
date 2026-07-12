/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_EARLY_CONSOLE_H
#define ARMOS_ARM64_EARLY_CONSOLE_H

typedef unsigned long long arm64_early_u64;

void arm64_early_putc(char c);
void arm64_early_puts(const char *text);
void arm64_early_puthex64(arm64_early_u64 value);

#endif

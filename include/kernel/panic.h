/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/panic.h
 * Layer: Kernel / diagnostics
 *
 * Responsibilities:
 * - Declare the fatal kernel panic entry point.
 *
 * Notes:
 * - Panic is intentionally small and global: it is used by arch code,
 *   memory management, tasking, and process bring-up.
 */

#ifndef _KERNEL_PANIC_H
#define _KERNEL_PANIC_H

void panic(const char* message) __attribute__((noreturn));

#endif /* _KERNEL_PANIC_H */

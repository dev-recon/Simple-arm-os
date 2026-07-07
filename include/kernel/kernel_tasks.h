/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kernel_tasks.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_TASKS_H
#define _KERNEL_TASKS_H

#include <kernel/types.h>

/* Statistiques et monitoring */
void print_system_stats(void);
void print_memory_stats(void);

#endif /* _KERNEL_TASKS_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/debug_print.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H

#include <kernel/types.h>

void debug_print_hex(const char* prefix, uint32_t value);
void debug_print_dec(const char* prefix, uint32_t value);
void simple_kprintf(const char* msg);

#endif

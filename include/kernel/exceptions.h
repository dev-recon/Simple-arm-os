/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/exceptions.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <kernel/types.h>

int data_abort_handler(uint32_t spsr_abt, uint32_t dfar, uint32_t dfsr, uint32_t *saved);
int coredumpd_start(void);
void arch_coredump_process_pending(void);

#endif

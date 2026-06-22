/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/math.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_MATH_H_
#define _KERNEL_MATH_H_

#include <kernel/types.h>

#define MOD(a, b) fast_modulo_power_of_2((a), (b))

uint16_t fast_modulo_power_of_2(uint16_t dividend, uint16_t divisor);

#endif
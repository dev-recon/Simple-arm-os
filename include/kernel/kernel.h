/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kernel.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_H
#define _KERNEL_H

#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/fdt.h>
#include <kernel/compiler.h>
#include <kernel/stddef.h>
#include <kernel/fd.h>
#include <kernel/linker.h>
#include <kernel/util.h>
#include <kernel/user_layout.h>
#include <kernel/address_space.h>
#include <kernel/panic.h>

//extern const uint32_t TASK_CONTEXT_OFF;

#endif /* _KERNEL_H */

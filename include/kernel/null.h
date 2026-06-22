/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/null.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_NULL_H
#define _KERNEL_NULL_H

#include <kernel/task.h>

#define DEV_NULL_RDEV  ((1u << 8) | 3u)

bool is_null_device_path(const char* path);
file_t* create_null_device_file(const char* name, int flags);
void fill_null_device_stat(struct stat* st);

#endif /* _KERNEL_NULL_H */

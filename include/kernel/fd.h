/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/fd.h
 * Layer: Kernel / file descriptor ABI
 *
 * Responsibilities:
 * - Define process standard file descriptor numbers.
 * - Keep POSIX-style descriptor constants out of the global kernel header.
 */

#ifndef KERNEL_FD_H
#define KERNEL_FD_H

#define STDIN_FILENO            0
#define STDOUT_FILENO           1
#define STDERR_FILENO           2

#endif /* KERNEL_FD_H */

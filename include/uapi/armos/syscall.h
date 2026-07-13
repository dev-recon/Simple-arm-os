/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/uapi/armos/syscall.h
 * Layer: UAPI / syscall ABI
 *
 * Responsibilities:
 * - Define syscall numbers shared by kernel and architecture entry paths.
 * - Preserve the Linux ARM32-compatible number space used by ArmOS userland.
 *
 * Notes:
 * - Each architecture defines its own register calling convention.
 * - sched_yield uses the established Linux-compatible syscall slot 158.
 */

#ifndef _UAPI_ARMOS_SYSCALL_H
#define _UAPI_ARMOS_SYSCALL_H

#define ARMOS_NR_EXIT       1
#define ARMOS_NR_FORK       2
#define ARMOS_NR_READ       3
#define ARMOS_NR_WRITE      4
#define ARMOS_NR_WAITPID    7
#define ARMOS_NR_EXECVE     11
#define ARMOS_NR_GETPID     20
#define ARMOS_NR_KILL       37
#define ARMOS_NR_BRK        45
#define ARMOS_NR_SIGACTION  67
#define ARMOS_NR_GETPPID    119
#define ARMOS_NR_SCHED_YIELD 158
#define ARMOS_NR_MMAP       195
#define ARMOS_NR_MUNMAP     196
#define ARMOS_SYSCALL_MAX 512

#endif

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/uapi/armos/file.h
 * Layer: UAPI / file ABI
 *
 * Responsibilities:
 * - Define architecture-independent file values used by ArmOS syscalls.
 * - Keep ARM32 and ARM64 newlib type widths out of the kernel ABI.
 *
 * Notes:
 * - Positioned I/O passes its offset through a pointer to this fixed layout.
 * - Current ArmOS filesystems use 32-bit inode sizes; wrappers reject larger
 *   offsets explicitly instead of allowing truncation in the kernel.
 */

#ifndef _UAPI_ARMOS_FILE_H
#define _UAPI_ARMOS_FILE_H

typedef struct {
    signed long long value;
} armos_offset_t;

#define ARMOS_FILE_OFFSET_MAX 0xffffffffULL

#endif

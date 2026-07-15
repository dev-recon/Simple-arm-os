/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/platform.h
 * Layer: ARM32 / platform selection
 *
 * Responsibilities:
 * - Select the active ARM32 board/platform description.
 * - Keep ARM32 CPU support separate from machine-specific MMIO addresses.
 *
 * Notes:
 * - Keep this dispatch intentionally simple: each real board gets its own
 *   header, and the shared ARM32 code includes only <asm/platform.h>.
 */

#ifndef _ASM_PLATFORM_H
#define _ASM_PLATFORM_H

#if defined(ARMOS_PLATFORM_QEMU_VIRT)
#include <asm/platform/qemu_virt.h>
#elif defined(ARMOS_PLATFORM_RASPI3)
#include <asm/platform/raspi3.h>
#elif defined(ARMOS_PLATFORM_RASPI2)
#include <asm/platform/raspi2.h>
#else
#error "No ARM32 platform selected. Define ARMOS_PLATFORM_QEMU_VIRT, ARMOS_PLATFORM_RASPI2, ARMOS_PLATFORM_RASPI3, or add a new platform header."
#endif

#endif /* _ASM_PLATFORM_H */

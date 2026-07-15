/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/platform.h
 * Layer: ARM64 / platform selection
 *
 * Responsibilities:
 * - Select the platform description used by the ARM64 CPU/MMU port.
 * - Keep board addresses out of generic kernel code.
 *
 * Notes:
 * - Platform policy belongs to the platform layer; this header is only the
 *   compile-time selection boundary expected by kernel/arch_platform.h.
 */

#ifndef ASM_ARM64_PLATFORM_H
#define ASM_ARM64_PLATFORM_H

#if defined(ARMOS_PLATFORM_QEMU_VIRT)
#include <asm/platform/qemu_virt.h>
#elif defined(ARMOS_PLATFORM_RASPI3)
#include <asm/platform/raspi3.h>
#else
#error "No ARM64 platform selected"
#endif

#endif /* ASM_ARM64_PLATFORM_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/arch_platform.h
 * Layer: Kernel / architecture boundary
 *
 * Responsibilities:
 * - Expose the active platform MMIO and IRQ map to drivers.
 * - Keep generic driver headers from including asm/platform.h directly.
 *
 * Notes:
 * - This is intentionally a thin boundary during the multi-arch migration.
 *   Once a second platform exists, stable names can move here and the
 *   arch-specific header can keep only its local implementation details.
 */

#ifndef _KERNEL_ARCH_PLATFORM_H
#define _KERNEL_ARCH_PLATFORM_H

#include <kernel/types.h>
#include <asm/platform.h>

static inline paddr_t arch_platform_uart0_phys_base(void)
{
    return (paddr_t)VIRT_UART_BASE;
}

static inline vaddr_t arch_platform_uart0_kernel_base(void)
{
    return (vaddr_t)KERNEL_MMIO_UART_BASE;
}

static inline paddr_t arch_platform_ram_start(void)
{
    return (paddr_t)VIRT_RAM_START;
}

static inline uint32_t arch_platform_timer_irq(void)
{
    return VIRT_TIMER_NS_EL1_IRQ;
}

static inline uint32_t arch_platform_uart_irq(void)
{
    return VIRT_UART_IRQ;
}

#endif /* _KERNEL_ARCH_PLATFORM_H */

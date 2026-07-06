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

static inline paddr_t arch_platform_device_start(void)
{
    return (paddr_t)DEVICE_START;
}

static inline paddr_t arch_platform_device_end(void)
{
    return (paddr_t)DEVICE_END;
}

static inline uint32_t arch_platform_kernel_mmio_section_size(void)
{
    return KERNEL_MMIO_SECTION_SIZE;
}

static inline vaddr_t arch_platform_kernel_mmio_gic_base(void)
{
    return (vaddr_t)KERNEL_MMIO_GIC_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_uart_base(void)
{
    return (vaddr_t)KERNEL_MMIO_UART_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_virtio_base(void)
{
    return (vaddr_t)KERNEL_MMIO_VIRTIO_BASE;
}

static inline paddr_t arch_platform_gic_phys_start(void)
{
    return (paddr_t)VIRT_GIC_DIST_BASE;
}

static inline paddr_t arch_platform_gic_phys_end(void)
{
    return (paddr_t)(VIRT_GIC_VCPU_BASE + VIRT_GIC_VCPU_SIZE);
}

static inline uint32_t arch_platform_timer_irq(void)
{
    return VIRT_TIMER_NS_EL1_IRQ;
}

static inline uint32_t arch_platform_uart_irq(void)
{
    return VIRT_UART_IRQ;
}

static inline volatile uint32_t* arch_platform_virtio_mmio_base(paddr_t phys)
{
    return (volatile uint32_t*)(uintptr_t)KERNEL_MMIO_VIRTIO_ADDR(phys);
}

static inline paddr_t arch_platform_virtio_phys_start(void)
{
    return (paddr_t)VIRT_VIRTIO_BASE;
}

static inline bool arch_platform_virtio_irq_from_phys(paddr_t phys, uint32_t* out_irq)
{
    if (!out_irq)
        return false;
    if (phys < arch_platform_virtio_phys_start())
        return false;
    if (((phys - arch_platform_virtio_phys_start()) % VIRT_VIRTIO_SIZE) != 0)
        return false;

    uint32_t index = (phys - arch_platform_virtio_phys_start()) / VIRT_VIRTIO_SIZE;
    *out_irq = VIRT_VIRTIO_IRQ(index);
    return true;
}

static inline paddr_t arch_platform_virtio_net_phys(void)
{
    return (paddr_t)VIRT_VIRTIO_NET;
}

static inline uint32_t arch_platform_virtio_net_irq(void)
{
    return VIRT_VIRTIO_NET_IRQ;
}

static inline paddr_t arch_platform_virtio_block_phys(void)
{
    return (paddr_t)VIRT_VIRTIO_BLOCK;
}

static inline paddr_t arch_platform_virtio_block_fallback_phys(void)
{
    return (paddr_t)(VIRT_VIRTIO_BASE + 31u * VIRT_VIRTIO_SIZE);
}

static inline uint32_t arch_platform_virtio_block_irq(void)
{
    return VIRT_VIRTIO_BLOCK_IRQ;
}

static inline uint32_t arch_platform_virtio_mmio_size(void)
{
    return VIRT_VIRTIO_SIZE;
}

static inline bool arch_platform_phys_is_device(paddr_t phys)
{
    return phys >= arch_platform_device_start() &&
           phys < arch_platform_device_end();
}

static inline bool arch_platform_phys_is_virtio(paddr_t phys)
{
    paddr_t start = arch_platform_virtio_phys_start();
    return phys >= start && phys < (start + VIRT_VIRTIO_SIZE * 8u);
}

static inline bool arch_platform_phys_is_gic(paddr_t phys)
{
    return phys >= arch_platform_gic_phys_start() &&
           phys < arch_platform_gic_phys_end();
}

#endif /* _KERNEL_ARCH_PLATFORM_H */

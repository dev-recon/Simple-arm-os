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

/*
 * Optional platform capabilities.
 *
 * A second board should not have to publish fake VirtIO/RTC addresses just
 * because qemu-virt has them. Defaults keep this header parseable while real
 * users still check the matching arch_platform_has_* helper before touching
 * optional MMIO windows.
 */
#ifndef ARMOS_PLATFORM_KERNEL_MMIO_RTC_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_RTC_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_HAS_PSCI
#define ARMOS_PLATFORM_HAS_PSCI 0u
#endif

#ifndef ARMOS_PLATFORM_HAS_SMP_IPI
#define ARMOS_PLATFORM_HAS_SMP_IPI 0u
#endif

#ifndef ARMOS_PLATFORM_TIMER_FORCE_HZ
#define ARMOS_PLATFORM_TIMER_FORCE_HZ 0u
#endif

#ifndef ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_HZ
#define ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_HZ 0u
#endif

#ifndef ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_EFFECTIVE_HZ
#define ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_EFFECTIVE_HZ 0u
#endif

#ifndef ARMOS_PLATFORM_DEFAULT_CPU_COUNT
#define ARMOS_PLATFORM_DEFAULT_CPU_COUNT 1u
#endif

#ifndef ARMOS_PLATFORM_UART0_PHYS_SECTION_BASE
#define ARMOS_PLATFORM_UART0_PHYS_SECTION_BASE ARMOS_PLATFORM_UART0_PHYS_BASE
#endif

#ifndef ARMOS_PLATFORM_KERNEL_MMIO_VIRTIO_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_VIRTIO_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_KERNEL_MMIO_EMMC_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_EMMC_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE
#define ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_HAS_EMMC
#define ARMOS_PLATFORM_HAS_EMMC 0u
#endif

#ifndef ARMOS_PLATFORM_EMMC_PHYS_BASE
#define ARMOS_PLATFORM_EMMC_PHYS_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_EMMC_PHYS_SECTION_BASE
#define ARMOS_PLATFORM_EMMC_PHYS_SECTION_BASE ARMOS_PLATFORM_EMMC_PHYS_BASE
#endif

#ifndef ARMOS_PLATFORM_EMMC_KERNEL_BASE
#define ARMOS_PLATFORM_EMMC_KERNEL_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_PHYS_START
#define ARMOS_PLATFORM_VIRTIO_PHYS_START 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_MMIO_SIZE
#define ARMOS_PLATFORM_VIRTIO_MMIO_SIZE 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_MMIO_ADDR
#define ARMOS_PLATFORM_VIRTIO_MMIO_ADDR(paddr) ((void)(paddr), 0u)
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_IRQ
#define ARMOS_PLATFORM_VIRTIO_IRQ(n) ((void)(n), 0u)
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_NET_PHYS
#define ARMOS_PLATFORM_VIRTIO_NET_PHYS 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_NET_IRQ
#define ARMOS_PLATFORM_VIRTIO_NET_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_BLOCK_PHYS
#define ARMOS_PLATFORM_VIRTIO_BLOCK_PHYS 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_BLOCK_FALLBACK_PHYS
#define ARMOS_PLATFORM_VIRTIO_BLOCK_FALLBACK_PHYS 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_BLOCK_IRQ
#define ARMOS_PLATFORM_VIRTIO_BLOCK_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_CONSOLE_IRQ
#define ARMOS_PLATFORM_VIRTIO_CONSOLE_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_VIRTIO_RNG_IRQ
#define ARMOS_PLATFORM_VIRTIO_RNG_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_SGI_TLB_SHOOTDOWN_IRQ
#define ARMOS_PLATFORM_SGI_TLB_SHOOTDOWN_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_KEYBOARD_IRQ
#define ARMOS_PLATFORM_KEYBOARD_IRQ 0u
#endif

#ifndef ARMOS_PLATFORM_PL050_KBD_BASE
#define ARMOS_PLATFORM_PL050_KBD_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_PCIE_PIO_BASE
#define ARMOS_PLATFORM_PCIE_PIO_BASE 0u
#endif

#ifndef ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED
#define ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED 0u
#endif

static inline const char* arch_platform_name(void)
{
    return ARMOS_PLATFORM_NAME;
}

static inline const char* arch_platform_cpu_model(void)
{
    return ARMOS_PLATFORM_CPU_MODEL;
}

static inline const char* arch_platform_cpu_features(void)
{
    return ARMOS_PLATFORM_CPU_FEATURES;
}

static inline const char* arch_platform_hardware_name(void)
{
    return ARMOS_PLATFORM_HARDWARE_NAME;
}

static inline paddr_t arch_platform_uart0_phys_base(void)
{
    return (paddr_t)ARMOS_PLATFORM_UART0_PHYS_BASE;
}

static inline paddr_t arch_platform_uart0_phys_section_base(void)
{
    return (paddr_t)ARMOS_PLATFORM_UART0_PHYS_SECTION_BASE;
}

static inline vaddr_t arch_platform_uart0_kernel_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_UART0_KERNEL_BASE;
}

static inline uint32_t arch_platform_uart0_clock_hz(void)
{
    return ARMOS_PLATFORM_UART0_CLOCK_HZ;
}

static inline uint32_t arch_platform_uart0_baud(void)
{
    return ARMOS_PLATFORM_UART0_BAUD;
}

static inline paddr_t arch_platform_ram_start(void)
{
    return (paddr_t)ARMOS_PLATFORM_RAM_START;
}

static inline uint32_t arch_platform_ram_fallback_size(void)
{
    return ARMOS_PLATFORM_RAM_FALLBACK_SIZE;
}

static inline uint32_t arch_platform_ram_probe_max_mb(void)
{
    return ARMOS_PLATFORM_RAM_PROBE_MAX_MB;
}

static inline uint32_t arch_platform_timer_fallback_hz(void)
{
    return ARMOS_PLATFORM_TIMER_FALLBACK_HZ;
}

static inline uint32_t arch_platform_timer_force_hz(void)
{
    return ARMOS_PLATFORM_TIMER_FORCE_HZ;
}

static inline uint32_t arch_platform_timer_effective_hz(uint32_t cntfrq)
{
    if (ARMOS_PLATFORM_TIMER_FORCE_HZ)
        return ARMOS_PLATFORM_TIMER_FORCE_HZ;

    if (ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_HZ &&
        ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_EFFECTIVE_HZ &&
        cntfrq == ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_HZ)
        return ARMOS_PLATFORM_TIMER_CNTFRQ_QUIRK_EFFECTIVE_HZ;

    return cntfrq ? cntfrq : ARMOS_PLATFORM_TIMER_FALLBACK_HZ;
}

static inline uint32_t arch_platform_default_cpu_count(void)
{
    return ARMOS_PLATFORM_DEFAULT_CPU_COUNT;
}

static inline paddr_t arch_platform_device_start(void)
{
    return (paddr_t)ARMOS_PLATFORM_DEVICE_START;
}

static inline paddr_t arch_platform_device_end(void)
{
    return (paddr_t)ARMOS_PLATFORM_DEVICE_END;
}

static inline uint32_t arch_platform_kernel_mmio_section_size(void)
{
    return ARMOS_PLATFORM_KERNEL_MMIO_SECTION_SIZE;
}

static inline vaddr_t arch_platform_kernel_mmio_irqctrl_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_uart_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_UART_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_rtc_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_RTC_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_virtio_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_VIRTIO_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_emmc_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_EMMC_BASE;
}

static inline vaddr_t arch_platform_kernel_mmio_irqctrl2_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE;
}

static inline paddr_t arch_platform_irqctrl2_phys_section_base(void)
{
    return (paddr_t)ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE;
}

static inline bool arch_platform_has_irqctrl2_alias(void)
{
    return ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE != 0u &&
           ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE != 0u;
}

static inline bool arch_platform_has_virtio_mmio(void)
{
    return ARMOS_PLATFORM_VIRTIO_MMIO_SIZE != 0u;
}

static inline bool arch_platform_has_emmc(void)
{
    return ARMOS_PLATFORM_HAS_EMMC != 0u;
}

static inline bool arch_platform_has_psci(void)
{
    return ARMOS_PLATFORM_HAS_PSCI != 0u;
}

static inline bool arch_platform_has_smp_ipi(void)
{
    return ARMOS_PLATFORM_HAS_SMP_IPI != 0u;
}

static inline bool arch_platform_has_pl050_keyboard(void)
{
    return ARMOS_PLATFORM_PL050_KBD_BASE != 0u && ARMOS_PLATFORM_KEYBOARD_IRQ != 0u;
}

static inline paddr_t arch_platform_irqctrl_phys_start(void)
{
    return (paddr_t)ARMOS_PLATFORM_IRQCTRL_PHYS_START;
}

static inline paddr_t arch_platform_irqctrl_phys_end(void)
{
    return (paddr_t)ARMOS_PLATFORM_IRQCTRL_PHYS_END;
}

static inline bool arch_platform_irq_targets_auto_managed(void)
{
    return ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED != 0;
}

static inline uint32_t arch_platform_timer_irq(void)
{
    return ARMOS_PLATFORM_TIMER_IRQ;
}

static inline uint32_t arch_platform_uart_irq(void)
{
    return ARMOS_PLATFORM_UART_IRQ;
}

static inline volatile uint32_t* arch_platform_virtio_mmio_base(paddr_t phys)
{
    return (volatile uint32_t*)(uintptr_t)ARMOS_PLATFORM_VIRTIO_MMIO_ADDR(phys);
}

static inline paddr_t arch_platform_virtio_phys_start(void)
{
    return (paddr_t)ARMOS_PLATFORM_VIRTIO_PHYS_START;
}

static inline bool arch_platform_virtio_irq_from_phys(paddr_t phys, uint32_t* out_irq)
{
    if (!out_irq)
        return false;
#if ARMOS_PLATFORM_VIRTIO_MMIO_SIZE == 0u
    (void)phys;
    return false;
#else
    if (!arch_platform_has_virtio_mmio())
        return false;
    if (phys < arch_platform_virtio_phys_start())
        return false;
    if (((phys - arch_platform_virtio_phys_start()) % ARMOS_PLATFORM_VIRTIO_MMIO_SIZE) != 0)
        return false;

    uint32_t index = (phys - arch_platform_virtio_phys_start()) / ARMOS_PLATFORM_VIRTIO_MMIO_SIZE;
    *out_irq = ARMOS_PLATFORM_VIRTIO_IRQ(index);
    return true;
#endif
}

static inline paddr_t arch_platform_virtio_net_phys(void)
{
    return (paddr_t)ARMOS_PLATFORM_VIRTIO_NET_PHYS;
}

static inline uint32_t arch_platform_virtio_net_irq(void)
{
    return ARMOS_PLATFORM_VIRTIO_NET_IRQ;
}

static inline paddr_t arch_platform_virtio_block_phys(void)
{
    return (paddr_t)ARMOS_PLATFORM_VIRTIO_BLOCK_PHYS;
}

static inline paddr_t arch_platform_virtio_block_fallback_phys(void)
{
    return (paddr_t)ARMOS_PLATFORM_VIRTIO_BLOCK_FALLBACK_PHYS;
}

static inline uint32_t arch_platform_virtio_block_irq(void)
{
    return ARMOS_PLATFORM_VIRTIO_BLOCK_IRQ;
}

static inline uint32_t arch_platform_virtio_mmio_size(void)
{
    return ARMOS_PLATFORM_VIRTIO_MMIO_SIZE;
}

static inline paddr_t arch_platform_emmc_phys_base(void)
{
    return (paddr_t)ARMOS_PLATFORM_EMMC_PHYS_BASE;
}

static inline paddr_t arch_platform_emmc_phys_section_base(void)
{
    return (paddr_t)ARMOS_PLATFORM_EMMC_PHYS_SECTION_BASE;
}

static inline vaddr_t arch_platform_emmc_kernel_base(void)
{
    return (vaddr_t)ARMOS_PLATFORM_EMMC_KERNEL_BASE;
}

static inline bool arch_platform_phys_is_device(paddr_t phys)
{
    return phys >= arch_platform_device_start() &&
           phys < arch_platform_device_end();
}

static inline bool arch_platform_phys_is_virtio(paddr_t phys)
{
#if ARMOS_PLATFORM_VIRTIO_MMIO_SIZE == 0u
    (void)phys;
    return false;
#else
    if (!arch_platform_has_virtio_mmio())
        return false;
    paddr_t start = arch_platform_virtio_phys_start();
    return phys >= start && phys < (start + ARMOS_PLATFORM_VIRTIO_MMIO_SIZE * 8u);
#endif
}

static inline bool arch_platform_phys_is_irqctrl(paddr_t phys)
{
    return phys >= arch_platform_irqctrl_phys_start() &&
           phys < arch_platform_irqctrl_phys_end();
}

#endif /* _KERNEL_ARCH_PLATFORM_H */

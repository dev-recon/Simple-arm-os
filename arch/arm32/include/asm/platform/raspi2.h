/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/platform/raspi2.h
 * Layer: ARM32 / Raspberry Pi 2 platform map
 *
 * Responsibilities:
 * - Define the first concrete Raspberry Pi 2 memory and MMIO contract.
 * - Keep the bring-up honest: UART-only first, no fake VirtIO/GIC devices.
 *
 * Notes:
 * - QEMU `raspi2b` and the real board both expose BCM2836-style peripherals,
 *   but the real board remains the final authority for timer, IRQ and SD/MMC
 *   behavior. This header deliberately publishes only the pieces we are ready
 *   to use.
 */

#ifndef _ASM_ARM32_PLATFORM_RASPI2_H
#define _ASM_ARM32_PLATFORM_RASPI2_H

#include <kernel/types.h>

#define RASPI2_RAM_START             0x00000000u
#define RASPI2_KERNEL_LINK_ADDR      0x02010000u

/*
 * Raspberry Pi 2 peripheral window. The PL011 UART lives inside the
 * 0x3F200000 GPIO/UART section, so the UART driver uses the exact register
 * base while the MMU maps the containing 1 MiB section as device memory.
 */
#define RASPI2_PERIPHERAL_BASE       0x3F000000u
#define RASPI2_PERIPHERAL_END        0x40000000u
#define RASPI2_IRQCTRL_BASE          0x3F00B000u
#define RASPI2_IRQCTRL_SECTION_BASE  0x3F000000u
#define RASPI2_LOCAL_IRQ_BASE        0x40000000u
#define RASPI2_LOCAL_IRQ_END         0x40100000u
#define RASPI2_UART0_BASE            0x3F201000u
#define RASPI2_UART0_SECTION_BASE    0x3F200000u
#define RASPI2_EMMC_BASE             0x3F300000u
#define RASPI2_EMMC_SECTION_BASE     0x3F300000u

#define RASPI2_KERNEL_MMIO_IRQ_BASE  0xF0000000u
#define RASPI2_KERNEL_MMIO_UART_BASE 0xF0100000u
#define RASPI2_KERNEL_MMIO_EMMC_BASE 0xF0200000u
#define RASPI2_KERNEL_MMIO_IRQCTRL2_BASE 0xF0300000u
#define RASPI2_KERNEL_MMIO_SECTION   0x00100000u

#define ARMOS_PLATFORM_NAME                      "Raspberry Pi 2"
#define ARMOS_PLATFORM_CPU_MODEL                 "ARM Cortex-A7 @ Raspberry Pi 2"
#define ARMOS_PLATFORM_CPU_FEATURES              "swp half thumb fastmult vfp edsp neon vfpv4 tls"
#define ARMOS_PLATFORM_HARDWARE_NAME             "ArmOS Raspberry Pi 2"
#define ARMOS_PLATFORM_RAM_START                 RASPI2_RAM_START
#define ARMOS_PLATFORM_RAM_FALLBACK_SIZE         (RASPI2_PERIPHERAL_BASE - RASPI2_RAM_START)
#define ARMOS_PLATFORM_RAM_PROBE_MAX_MB          1008u
#define ARMOS_PLATFORM_TIMER_FALLBACK_HZ         19200000u
#define ARMOS_PLATFORM_DEVICE_START              RASPI2_PERIPHERAL_BASE
#define ARMOS_PLATFORM_DEVICE_END                RASPI2_PERIPHERAL_END

#define ARMOS_PLATFORM_UART0_PHYS_BASE           RASPI2_UART0_BASE
#define ARMOS_PLATFORM_UART0_PHYS_SECTION_BASE   RASPI2_UART0_SECTION_BASE
#define ARMOS_PLATFORM_UART0_KERNEL_BASE \
    (RASPI2_KERNEL_MMIO_UART_BASE + (RASPI2_UART0_BASE - RASPI2_UART0_SECTION_BASE))
#define ARMOS_PLATFORM_UART0_CLOCK_HZ            3000000u
#define ARMOS_PLATFORM_UART0_BAUD                115200u

/*
 * The generic timer is routed through the BCM2836 ARM-local interrupt block.
 * PL011 keeps the Linux/BCM IRQ number and is bridged through the secondary
 * BCM2835-compatible interrupt controller by the raspi2 IRQ backend.
 */
#define ARMOS_PLATFORM_UART_IRQ                  57u
#define ARMOS_PLATFORM_TIMER_IRQ                 1u
#define ARMOS_PLATFORM_SGI_TLB_SHOOTDOWN_IRQ     0u

#define ARMOS_PLATFORM_KERNEL_MMIO_SECTION_SIZE  RASPI2_KERNEL_MMIO_SECTION
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL_BASE  RASPI2_KERNEL_MMIO_IRQ_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_UART_BASE     RASPI2_KERNEL_MMIO_UART_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_EMMC_BASE     RASPI2_KERNEL_MMIO_EMMC_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE \
    RASPI2_KERNEL_MMIO_IRQCTRL2_BASE
#define ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE \
    RASPI2_IRQCTRL_SECTION_BASE

#define ARMOS_PLATFORM_HAS_EMMC                  1u
#define ARMOS_PLATFORM_EMMC_PHYS_BASE            RASPI2_EMMC_BASE
#define ARMOS_PLATFORM_EMMC_PHYS_SECTION_BASE    RASPI2_EMMC_SECTION_BASE
#define ARMOS_PLATFORM_EMMC_KERNEL_BASE \
    (RASPI2_KERNEL_MMIO_EMMC_BASE + (RASPI2_EMMC_BASE - RASPI2_EMMC_SECTION_BASE))

#define ARMOS_PLATFORM_IRQCTRL_PHYS_START        RASPI2_LOCAL_IRQ_BASE
#define ARMOS_PLATFORM_IRQCTRL_PHYS_END          RASPI2_LOCAL_IRQ_END
#define ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED  0
#define ARMOS_PLATFORM_HAS_PSCI                  0

#endif /* _ASM_ARM32_PLATFORM_RASPI2_H */

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/include/asm/platform/qemu_virt.h
 * Layer: ARM32 / QEMU virt platform map
 *
 * Responsibilities:
 * - Define the physical MMIO layout used by the current ARM32 QEMU virt port.
 * - Define the kernel-side MMIO aliases used after the split TTBR setup.
 * - Keep board/platform addresses out of generic kernel headers.
 *
 * Notes:
 * - Public macro names stay stable during the multi-arch migration. A future
 *   ARM32 board or AArch64 port can provide its own platform header.
 */

#ifndef _ASM_ARM32_PLATFORM_QEMU_VIRT_H
#define _ASM_ARM32_PLATFORM_QEMU_VIRT_H

#include <kernel/types.h>

/* Physical RAM base for QEMU virt. */
#define VIRT_RAM_START          0x40000000u

#if VIRT_RAM_START != 0x40000000u
#error "ARM32 QEMU virt RAM must start at 0x40000000"
#endif

/* Memory map: QEMU virt platform. */
#define VIRT_FLASH_BASE         0x00000000u
#define VIRT_FLASH_SIZE         0x08000000u

/* GICv2. */
#define VIRT_GIC_DIST_BASE      0x08000000u
#define VIRT_GIC_DIST_SIZE      0x00010000u
#define VIRT_GIC_CPU_BASE       0x08010000u
#define VIRT_GIC_CPU_SIZE       0x00010000u
#define VIRT_GIC_V2M_BASE       0x08020000u
#define VIRT_GIC_V2M_SIZE       0x00001000u
#define VIRT_GIC_HYP_BASE       0x08030000u
#define VIRT_GIC_HYP_SIZE       0x00010000u
#define VIRT_GIC_VCPU_BASE      0x08040000u
#define VIRT_GIC_VCPU_SIZE      0x00010000u

/* PL011/PL031 and low platform devices. */
#define VIRT_UART_BASE          0x09000000u
#define VIRT_UART_SIZE          0x00001000u
#define VIRT_UART_IRQ           1

#define VIRT_RTC_BASE           0x09010000u
#define VIRT_RTC_SIZE           0x00001000u
#define VIRT_RTC_IRQ            2

#define VIRT_FW_CFG_BASE        0x09020000u
#define VIRT_FW_CFG_SIZE        0x00000018u

#define VIRT_GPIO_BASE          0x09030000u
#define VIRT_GPIO_SIZE          0x00001000u
#define VIRT_GPIO_IRQ           7

#define VIRT_SECURE_UART_BASE   0x09040000u
#define VIRT_SECURE_UART_SIZE   0x00001000u

/* SGI/PPI/SPI IDs used by the current interrupt backend. */
#define VIRT_SGI_TLB_SHOOTDOWN_IRQ 14
#define VIRT_UART_LEGACY_IRQ    33
#define VIRT_ATA_LEGACY_IRQ     34

/* Legacy PL050 keyboard fallback. Normal graphical input uses virtio-input. */
#define VIRT_PL050_KBD_BASE     0x09060000u
#define VIRT_PL050_KBD_SIZE     0x00001000u

/* VirtIO MMIO region. */
#define VIRT_VIRTIO_BASE        0x0A000000u
#define VIRT_VIRTIO_SIZE        0x00000200u
#define VIRT_VIRTIO_IRQ_BASE    16

/*
 * Private TTBR1 MMIO aliases. Drivers are still being migrated away from low
 * physical addresses; these aliases let kernel-only MMIO stay outside future
 * user TTBR0 address spaces.
 */
#define KERNEL_MMIO_GIC_BASE     0xF0000000u
#define KERNEL_MMIO_UART_BASE    0xF0100000u
#define KERNEL_MMIO_VIRTIO_BASE  0xF0200000u
#define KERNEL_MMIO_SECTION_SIZE 0x00100000u

#define KERNEL_MMIO_GIC_DIST_BASE KERNEL_MMIO_GIC_BASE
#define KERNEL_MMIO_GIC_CPU_BASE  (KERNEL_MMIO_GIC_BASE + (VIRT_GIC_CPU_BASE - VIRT_GIC_DIST_BASE))
#define KERNEL_MMIO_RTC_BASE      (KERNEL_MMIO_UART_BASE + (VIRT_RTC_BASE - VIRT_UART_BASE))
#define KERNEL_MMIO_VIRTIO_ADDR(paddr) \
    ((vaddr_t)(KERNEL_MMIO_VIRTIO_BASE + ((paddr_t)(paddr) - VIRT_VIRTIO_BASE)))

/* Compatibility aliases used by existing drivers. */
#define VIRTIO_BASE             VIRT_VIRTIO_BASE
#define VIRTIO_SIZE             VIRT_VIRTIO_SIZE
#define VIRTIO_IRQ_BASE         VIRT_VIRTIO_IRQ_BASE

#define VIRT_VIRTIO_DEVICE(n)   (VIRT_VIRTIO_BASE + (n) * VIRT_VIRTIO_SIZE)
#define VIRT_VIRTIO_IRQ(n)      (VIRT_VIRTIO_IRQ_BASE + (n))

#define VIRT_VIRTIO_NET         VIRT_VIRTIO_DEVICE(0)
#define VIRT_VIRTIO_BLOCK       VIRT_VIRTIO_DEVICE(1)
#define VIRT_VIRTIO_CONSOLE     VIRT_VIRTIO_DEVICE(2)
#define VIRT_VIRTIO_RNG         VIRT_VIRTIO_DEVICE(3)

#define VIRT_VIRTIO_NET_IRQ     VIRT_VIRTIO_IRQ(0)
#define VIRT_VIRTIO_BLOCK_IRQ   VIRT_VIRTIO_IRQ(1)
#define VIRT_VIRTIO_CONSOLE_IRQ VIRT_VIRTIO_IRQ(2)
#define VIRT_VIRTIO_RNG_IRQ     VIRT_VIRTIO_IRQ(3)

#define VIRTIO_DEVICE(n)        VIRT_VIRTIO_DEVICE(n)
#define VIRTIO_IRQ(n)           VIRT_VIRTIO_IRQ(n)

/* PCIe ranges exposed by QEMU virt. */
#define VIRT_PCIE_MMIO_BASE     0x10000000u
#define VIRT_PCIE_MMIO_SIZE     0x2EFF0000u
#define VIRT_PCIE_PIO_BASE      0x3EFF0000u
#define VIRT_PCIE_PIO_SIZE      0x00010000u
#define VIRT_PCIE_ECAM_BASE     0x3F000000u
#define VIRT_PCIE_ECAM_SIZE     0x01000000u

/*
 * Legacy IDE probing constants. The current ARM32 QEMU virt configuration
 * still exposes this path for the old IDE fallback driver; keep the exact
 * historical values here so generic storage headers do not own platform MMIO.
 */
#define VIRT_IDE_PRIMARY_BASE   0x3F000000u
#define VIRT_IDE_PRIMARY_CTRL   0x3F00000Eu
#define VIRT_IDE_PRIMARY_IRQ    14
#define VIRT_IDE_LEGACY_IO_BASE (VIRT_PCIE_PIO_BASE + 0x1F0u)

/* ARM generic timer interrupt IDs on QEMU virt. */
#define VIRT_TIMER_NS_EL1_IRQ   30
#define VIRT_TIMER_S_EL1_IRQ    29
#define VIRT_TIMER_HYP_IRQ      26
#define VIRT_TIMER_VIRT_IRQ     27

/* Legacy generic names used by older driver code. */
#define UART0_BASE              VIRT_UART_BASE
#define UART1_BASE              (VIRT_UART_BASE + 0x1000)
#define UART2_BASE              (VIRT_UART_BASE + 0x2000)
#define UART3_BASE              (VIRT_UART_BASE + 0x3000)

#define TIMER0_BASE             0x09000000u
#define TIMER1_BASE             0x09000000u

#define GPIO0_BASE              VIRT_GPIO_BASE
#define GPIO1_BASE              (VIRT_GPIO_BASE + 0x1000)

#define RTC_BASE                VIRT_RTC_BASE

#define DEVICE_START            0x08000000u
#define DEVICE_END              0x40000000u
#define PERIPHERAL_START        0x08000000u
#define PERIPHERAL_END          0x40000000u

/*
 * Generic platform contract consumed by include/kernel/arch_platform.h.
 * Keep the historical VIRT_* names local to this QEMU virt description.
 */
#define ARMOS_PLATFORM_NAME                      "QEMU virt"
#define ARMOS_PLATFORM_CPU_MODEL                 "ARM Cortex-A15 @ QEMU virt"
#define ARMOS_PLATFORM_CPU_FEATURES              "swp half thumb fastmult vfp edsp neon vfpv4 tls"
#define ARMOS_PLATFORM_HARDWARE_NAME             "ArmOS QEMU virt"
#define ARMOS_PLATFORM_RAM_START                 VIRT_RAM_START
#define ARMOS_PLATFORM_RAM_FALLBACK_SIZE         (1024u * 1024u * 1024u)
#define ARMOS_PLATFORM_RAM_PROBE_MAX_MB          4096u
#define ARMOS_PLATFORM_TIMER_FALLBACK_HZ         62500000u
#define ARMOS_PLATFORM_DEVICE_START              DEVICE_START
#define ARMOS_PLATFORM_DEVICE_END                DEVICE_END

#define ARMOS_PLATFORM_UART0_PHYS_BASE           VIRT_UART_BASE
#define ARMOS_PLATFORM_UART0_KERNEL_BASE         KERNEL_MMIO_UART_BASE
#define ARMOS_PLATFORM_UART0_CLOCK_HZ            48000000u
#define ARMOS_PLATFORM_UART0_BAUD                115200u
#define ARMOS_PLATFORM_UART_IRQ                  VIRT_UART_IRQ

#define ARMOS_PLATFORM_KERNEL_MMIO_SECTION_SIZE  KERNEL_MMIO_SECTION_SIZE
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL_BASE  KERNEL_MMIO_GIC_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_UART_BASE     KERNEL_MMIO_UART_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_RTC_BASE      KERNEL_MMIO_RTC_BASE
#define ARMOS_PLATFORM_KERNEL_MMIO_VIRTIO_BASE   KERNEL_MMIO_VIRTIO_BASE

/* QEMU virt local GIC backend aliases, not part of the generic contract. */
#define QEMU_VIRT_KERNEL_MMIO_GIC_DIST_BASE      KERNEL_MMIO_GIC_DIST_BASE
#define QEMU_VIRT_KERNEL_MMIO_GIC_CPU_BASE       KERNEL_MMIO_GIC_CPU_BASE

#define ARMOS_PLATFORM_IRQCTRL_PHYS_START        VIRT_GIC_DIST_BASE
#define ARMOS_PLATFORM_IRQCTRL_PHYS_END          (VIRT_GIC_VCPU_BASE + VIRT_GIC_VCPU_SIZE)
#define ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED  1

#define ARMOS_PLATFORM_SGI_TLB_SHOOTDOWN_IRQ     VIRT_SGI_TLB_SHOOTDOWN_IRQ
#define ARMOS_PLATFORM_TIMER_IRQ                 VIRT_TIMER_NS_EL1_IRQ
#define ARMOS_PLATFORM_KEYBOARD_IRQ              VIRT_UART_LEGACY_IRQ
#define ARMOS_PLATFORM_ATA_IRQ                   VIRT_ATA_LEGACY_IRQ

#define ARMOS_PLATFORM_PL050_KBD_BASE            VIRT_PL050_KBD_BASE

#define ARMOS_PLATFORM_IDE_PRIMARY_BASE          VIRT_IDE_PRIMARY_BASE
#define ARMOS_PLATFORM_IDE_PRIMARY_CTRL          VIRT_IDE_PRIMARY_CTRL
#define ARMOS_PLATFORM_IDE_PRIMARY_IRQ           VIRT_IDE_PRIMARY_IRQ
#define ARMOS_PLATFORM_PCIE_PIO_BASE             VIRT_PCIE_PIO_BASE
#define ARMOS_PLATFORM_IDE_LEGACY_IO_BASE        VIRT_IDE_LEGACY_IO_BASE

#define ARMOS_PLATFORM_VIRTIO_PHYS_START         VIRT_VIRTIO_BASE
#define ARMOS_PLATFORM_VIRTIO_MMIO_SIZE          VIRT_VIRTIO_SIZE
#define ARMOS_PLATFORM_VIRTIO_IRQ_BASE           VIRT_VIRTIO_IRQ_BASE
#define ARMOS_PLATFORM_VIRTIO_MMIO_ADDR(paddr)   KERNEL_MMIO_VIRTIO_ADDR(paddr)
#define ARMOS_PLATFORM_VIRTIO_IRQ(n)             VIRT_VIRTIO_IRQ(n)

#define ARMOS_PLATFORM_VIRTIO_NET_PHYS           VIRT_VIRTIO_NET
#define ARMOS_PLATFORM_VIRTIO_NET_IRQ            VIRT_VIRTIO_NET_IRQ
#define ARMOS_PLATFORM_VIRTIO_BLOCK_PHYS         VIRT_VIRTIO_BLOCK
#define ARMOS_PLATFORM_VIRTIO_BLOCK_FALLBACK_PHYS \
    (VIRT_VIRTIO_BASE + 31u * VIRT_VIRTIO_SIZE)
#define ARMOS_PLATFORM_VIRTIO_BLOCK_IRQ          VIRT_VIRTIO_BLOCK_IRQ
#define ARMOS_PLATFORM_VIRTIO_CONSOLE_IRQ        VIRT_VIRTIO_CONSOLE_IRQ
#define ARMOS_PLATFORM_VIRTIO_RNG_IRQ            VIRT_VIRTIO_RNG_IRQ

#endif /* _ASM_ARM32_PLATFORM_QEMU_VIRT_H */

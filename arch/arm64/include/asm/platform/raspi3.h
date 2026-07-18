/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/platform/raspi3.h
 * Layer: ARM64 / Raspberry Pi 3 hardware map
 *
 * Responsibilities:
 * - Describe the BCM2837 memory and MMIO map used in AArch64 mode.
 * - Publish the shared Raspberry Pi device contract to the common kernel.
 *
 * Notes:
 * - The firmware loads kernel8.img at the configured 32 MiB address.
 * - In AArch64 mode the architectural counter advances at the 19.2 MHz rate
 *   reported by CNTFRQ_EL0; the AArch32 1 MHz counter quirk does not apply.
 * - CPU and MMU mechanisms remain under arch/arm64; BCM283x controllers live
 *   under kernel/platform/raspberrypi.
 */

#ifndef ASM_ARM64_PLATFORM_RASPI3_H
#define ASM_ARM64_PLATFORM_RASPI3_H

#include <asm/mmu.h>

#define RASPI3_RAM_START                 0x00000000ULL
#define RASPI3_RAM_FALLBACK_SIZE         0x3B400000ULL
#define RASPI3_PERIPHERAL_BASE           0x3F000000ULL
#define RASPI3_PERIPHERAL_END            0x40000000ULL
#define RASPI3_IRQCTRL_BASE              0x3F00B000ULL
#define RASPI3_IRQCTRL_SECTION_BASE      0x3F000000ULL
#define RASPI3_LOCAL_IRQ_BASE            0x40000000ULL
#define RASPI3_LOCAL_IRQ_END             0x40100000ULL
#define RASPI3_UART0_BASE                0x3F201000ULL
#define RASPI3_UART0_SECTION_BASE        0x3F200000ULL
#define RASPI3_GPIO_BASE                 0x3F200000ULL
#define RASPI3_EMMC_BASE                 0x3F300000ULL
#define RASPI3_EMMC_SECTION_BASE         0x3F300000ULL

#define ARMOS_PLATFORM_NAME                     "Raspberry Pi 3"
#define ARMOS_PLATFORM_CPU_MODEL                \
    "ARM Cortex-A53 @ Raspberry Pi 3 (AArch64)"
#define ARMOS_PLATFORM_CPU_FEATURES             \
    "fp asimd evtstrm aes pmull sha1 sha2 crc32"
#define ARMOS_PLATFORM_HARDWARE_NAME            "ArmOS Raspberry Pi 3"

#define ARMOS_PLATFORM_RAM_START                RASPI3_RAM_START
#define ARMOS_PLATFORM_RAM_FALLBACK_SIZE        RASPI3_RAM_FALLBACK_SIZE
#define ARMOS_PLATFORM_RAM_PROBE_MAX_MB         948u
#define ARMOS_PLATFORM_DEVICE_START             RASPI3_PERIPHERAL_BASE
#define ARMOS_PLATFORM_DEVICE_END               RASPI3_LOCAL_IRQ_END

#define ARMOS_PLATFORM_UART0_PHYS_BASE          RASPI3_UART0_BASE
#define ARMOS_PLATFORM_UART0_PHYS_SECTION_BASE  RASPI3_UART0_SECTION_BASE
#define ARMOS_PLATFORM_UART0_KERNEL_BASE        \
    (ARM64_KERNEL_VA_BASE + RASPI3_UART0_BASE)
#define ARMOS_PLATFORM_UART0_CLOCK_HZ           4000000u
#define ARMOS_PLATFORM_UART0_BAUD               115200u
#define ARMOS_PLATFORM_GPIO_KERNEL_BASE         \
    (ARM64_KERNEL_VA_BASE + RASPI3_GPIO_BASE)

/* 2.8-inch ILI9341 shield, write-only 8080 bus; RD is tied high. */
#define ARMOS_PLATFORM_ILI9341_D0_PIN            4u
#define ARMOS_PLATFORM_ILI9341_D1_PIN            17u
#define ARMOS_PLATFORM_ILI9341_D2_PIN            18u
#define ARMOS_PLATFORM_ILI9341_D3_PIN            27u
#define ARMOS_PLATFORM_ILI9341_D4_PIN            22u
#define ARMOS_PLATFORM_ILI9341_D5_PIN            23u
#define ARMOS_PLATFORM_ILI9341_D6_PIN            24u
#define ARMOS_PLATFORM_ILI9341_D7_PIN            25u
#define ARMOS_PLATFORM_ILI9341_CS_PIN             5u
#define ARMOS_PLATFORM_ILI9341_DC_PIN             6u
#define ARMOS_PLATFORM_ILI9341_WR_PIN             12u
#define ARMOS_PLATFORM_ILI9341_RESET_PIN          13u
#define ARMOS_PLATFORM_UART_IRQ                 57u

#define ARMOS_PLATFORM_TIMER_FALLBACK_HZ        1000000u
#define ARMOS_PLATFORM_TIMER_IRQ                1u
#define ARMOS_PLATFORM_DEFAULT_CPU_COUNT        4u

#define ARMOS_PLATFORM_KERNEL_MMIO_SECTION_SIZE 0x00200000ULL
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL_BASE \
    (ARM64_KERNEL_VA_BASE + RASPI3_LOCAL_IRQ_BASE)
#define ARMOS_PLATFORM_KERNEL_MMIO_UART_BASE    \
    (ARM64_KERNEL_VA_BASE + RASPI3_UART0_BASE)
#define ARMOS_PLATFORM_KERNEL_MMIO_EMMC_BASE    \
    (ARM64_KERNEL_VA_BASE + RASPI3_EMMC_BASE)
#define ARMOS_PLATFORM_KERNEL_MMIO_IRQCTRL2_BASE \
    (ARM64_KERNEL_VA_BASE + RASPI3_IRQCTRL_SECTION_BASE)

#define ARMOS_PLATFORM_IRQCTRL_PHYS_START       RASPI3_LOCAL_IRQ_BASE
#define ARMOS_PLATFORM_IRQCTRL_PHYS_END         RASPI3_LOCAL_IRQ_END
#define ARMOS_PLATFORM_IRQCTRL2_PHYS_BASE       RASPI3_IRQCTRL_BASE
#define ARMOS_PLATFORM_IRQCTRL2_PHYS_SECTION_BASE \
    RASPI3_IRQCTRL_SECTION_BASE

#define ARMOS_PLATFORM_HAS_EMMC                 1u
#define ARMOS_PLATFORM_EMMC_PHYS_BASE           RASPI3_EMMC_BASE
#define ARMOS_PLATFORM_EMMC_PHYS_SECTION_BASE   RASPI3_EMMC_SECTION_BASE
#define ARMOS_PLATFORM_EMMC_KERNEL_BASE         \
    (ARM64_KERNEL_VA_BASE + RASPI3_EMMC_BASE)

#define ARMOS_PLATFORM_HAS_PSCI                 0u
#define ARMOS_PLATFORM_HAS_SMP_IPI              1u
#define ARMOS_PLATFORM_SGI_TLB_SHOOTDOWN_IRQ    0u
#define ARMOS_PLATFORM_IRQ_TARGETS_AUTO_MANAGED 0u

#endif /* ASM_ARM64_PLATFORM_RASPI3_H */

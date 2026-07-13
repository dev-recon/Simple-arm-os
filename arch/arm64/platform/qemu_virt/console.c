/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/platform/qemu_virt/console.c
 * Layer: ARM64 / QEMU virt console
 *
 * Responsibilities:
 * - Drive the QEMU virt PL011 UART for bootstrap, diagnostics and TTY input.
 * - Preserve newline translation across the physical and high MMU aliases.
 *
 * Notes:
 * - The driver is polling-only until the persistent ARM64 TTY is connected.
 */

#include <asm/console.h>
#include <asm/mmu.h>

typedef unsigned int uint32_t;

#define PL011_BASE    0x09000000UL
#define PL011_DR      0x000u
#define PL011_FR      0x018u
#define PL011_FR_RXFE (1u << 4)
#define PL011_FR_TXFF (1u << 5)

static inline void mmio_write32(unsigned long address, uint32_t value)
{
    address = (unsigned long)arm64_mmu_kernel_address(address);
    *(volatile uint32_t *)address = value;
}

static inline uint32_t mmio_read32(unsigned long address)
{
    address = (unsigned long)arm64_mmu_kernel_address(address);
    return *(volatile uint32_t *)address;
}

void arm64_console_putc(char c)
{
    if (c == '\n')
        arm64_console_putc('\r');

    while (mmio_read32(PL011_BASE + PL011_FR) & PL011_FR_TXFF)
        __asm__ volatile("yield");

    mmio_write32(PL011_BASE + PL011_DR, (uint32_t)c);
}

void putchar_kernel(char c)
{
    arm64_console_putc(c);
}

void arm64_console_puts(const char *text)
{
    while (text && *text)
        arm64_console_putc(*text++);
}

void arm64_console_puthex64(arm64_console_u64 value)
{
    static const char digits[] = "0123456789ABCDEF";
    int shift;

    arm64_console_puts("0x");
    for (shift = 60; shift >= 0; shift -= 4)
        arm64_console_putc(digits[(value >> shift) & 0xfu]);
}

int arm64_console_try_getc(char *character)
{
    if (!character || (mmio_read32(PL011_BASE + PL011_FR) &
                       PL011_FR_RXFE) != 0)
        return 0;

    *character = (char)(mmio_read32(PL011_BASE + PL011_DR) & 0xffu);
    return 1;
}

char arm64_console_getc(void)
{
    char character;

    while (!arm64_console_try_getc(&character))
        __asm__ volatile("yield");
    return character;
}

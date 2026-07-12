/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal GICv2 and ARM physical timer bring-up for QEMU virt.
 */

#include <asm/early_console.h>
#include <asm/irq.h>

typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

#define GICD_BASE 0x08000000UL
#define GICC_BASE 0x08010000UL

#define GICD_CTLR        0x000u
#define GICD_TYPER       0x004u
#define GICD_ISENABLER   0x100u
#define GICD_ICENABLER   0x180u
#define GICD_IPRIORITYR  0x400u

#define GICC_CTLR        0x000u
#define GICC_PMR         0x004u
#define GICC_BPR         0x008u
#define GICC_IAR         0x00cu
#define GICC_EOIR        0x010u

#define ARM64_PHYS_TIMER_PPI 30u
#define GIC_SPURIOUS_IRQ     1023u
#define TIMER_TEST_TICKS     3u

static volatile uint32_t timer_ticks;
static volatile uint32_t unexpected_irq;
static uint64_t timer_interval;
static uint64_t timer_frequency;

static inline void mmio_write32(unsigned long address, uint32_t value)
{
    *(volatile uint32_t *)address = value;
}

static inline uint32_t mmio_read32(unsigned long address)
{
    return *(volatile uint32_t *)address;
}

static inline void mmio_write8(unsigned long address, uint8_t value)
{
    *(volatile uint8_t *)address = value;
}

static inline void timer_write_tval(uint64_t value)
{
    __asm__ volatile("msr cntp_tval_el0, %0" :: "r"(value));
}

static inline void timer_write_ctl(uint64_t value)
{
    __asm__ volatile("msr cntp_ctl_el0, %0" :: "r"(value));
    __asm__ volatile("isb");
}

static uint64_t timer_read_frequency(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

void arm64_irq_dispatch(void)
{
    uint32_t iar = mmio_read32(GICC_BASE + GICC_IAR);
    uint32_t irq = iar & 0x3ffu;

    if (irq == GIC_SPURIOUS_IRQ)
        return;

    if (irq == ARM64_PHYS_TIMER_PPI) {
        timer_ticks++;
        if (timer_ticks < TIMER_TEST_TICKS)
            timer_write_tval(timer_interval);
        else
            timer_write_ctl(0);
    } else {
        unexpected_irq = irq + 1u;
    }

    mmio_write32(GICC_BASE + GICC_EOIR, iar);
}

int arm64_timer_irq_smoke_test(void)
{
    uint32_t gic_type;

    timer_ticks = 0;
    unexpected_irq = 0;
    timer_frequency = timer_read_frequency();
    if (timer_frequency == 0)
        return -1;

    timer_interval = timer_frequency / 100u;
    if (timer_interval == 0)
        timer_interval = 1;

    mmio_write32(GICC_BASE + GICC_CTLR, 0);
    mmio_write32(GICD_BASE + GICD_CTLR, 0);
    __asm__ volatile("dsb sy" ::: "memory");

    gic_type = mmio_read32(GICD_BASE + GICD_TYPER);
    if ((gic_type & 0x1fu) == 0)
        return -2;

    mmio_write32(GICD_BASE + GICD_ICENABLER, 0xffffffffu);
    mmio_write8(GICD_BASE + GICD_IPRIORITYR + ARM64_PHYS_TIMER_PPI, 0x80u);
    mmio_write32(GICD_BASE + GICD_ISENABLER,
                 1u << ARM64_PHYS_TIMER_PPI);

    mmio_write32(GICC_BASE + GICC_PMR, 0xffu);
    mmio_write32(GICC_BASE + GICC_BPR, 0);
    mmio_write32(GICC_BASE + GICC_CTLR, 1);
    mmio_write32(GICD_BASE + GICD_CTLR, 1);

    timer_write_tval(timer_interval);
    timer_write_ctl(1);

    __asm__ volatile("dsb sy" ::: "memory");
    __asm__ volatile("msr daifclr, #2");
    __asm__ volatile("isb");

    while (timer_ticks < TIMER_TEST_TICKS && unexpected_irq == 0)
        __asm__ volatile("wfi");

    __asm__ volatile("msr daifset, #2");
    __asm__ volatile("isb");
    timer_write_ctl(0);
    mmio_write32(GICD_BASE + GICD_ICENABLER,
                 1u << ARM64_PHYS_TIMER_PPI);

    arm64_early_puts("CNTFRQ_EL0: ");
    arm64_early_puthex64(timer_frequency);
    arm64_early_puts(" timer ticks: ");
    arm64_early_puthex64(timer_ticks);
    arm64_early_puts("\n");

    if (unexpected_irq != 0)
        return -3;
    if (timer_ticks != TIMER_TEST_TICKS)
        return -4;

    arm64_early_puts("ARM64_TIMER_IRQ_OK\n");
    return 0;
}

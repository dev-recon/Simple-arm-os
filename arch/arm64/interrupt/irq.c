/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/interrupt/irq.c
 * Layer: ARM64 / QEMU virt interrupt controller
 *
 * Responsibilities:
 * - Bring up the QEMU virt GICv2 CPU and distributor interfaces.
 * - Drive the ARM physical timer PPI with bounded one-shot sequences.
 * - Acknowledge and classify IRQs before returning events to exception code.
 *
 * Notes:
 * - Scheduling policy is deliberately absent from this device-facing layer.
 * - The timer helpers reinitialize GIC state for deterministic boot probes.
 */

#include <asm/early_console.h>
#include <asm/irq.h>
#include <asm/mmu.h>

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
static uint32_t timer_target_ticks;
static uint64_t timer_interval;
static uint64_t timer_frequency;

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

static inline void mmio_write8(unsigned long address, uint8_t value)
{
    address = (unsigned long)arm64_mmu_kernel_address(address);
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

uint32_t arm64_irq_dispatch(void)
{
    uint32_t iar = mmio_read32(GICC_BASE + GICC_IAR);
    uint32_t irq = iar & 0x3ffu;
    uint32_t events = ARM64_IRQ_EVENT_NONE;

    if (irq == GIC_SPURIOUS_IRQ)
        return events;

    if (irq == ARM64_PHYS_TIMER_PPI) {
        timer_ticks++;
        events |= ARM64_IRQ_EVENT_TIMER;
        if (timer_ticks < timer_target_ticks)
            timer_write_tval(timer_interval);
        else
            timer_write_ctl(0);
    } else {
        unexpected_irq = irq + 1u;
    }

    mmio_write32(GICC_BASE + GICC_EOIR, iar);
    return events;
}

static int timer_irq_prepare(uint32_t target_ticks)
{
    uint32_t gic_type;

    if (target_ticks == 0)
        return -1;
    timer_ticks = 0;
    unexpected_irq = 0;
    timer_target_ticks = target_ticks;
    timer_frequency = timer_read_frequency();
    if (timer_frequency == 0)
        return -2;

    timer_interval = timer_frequency / 100u;
    if (timer_interval == 0)
        timer_interval = 1;

    mmio_write32(GICC_BASE + GICC_CTLR, 0);
    mmio_write32(GICD_BASE + GICD_CTLR, 0);
    __asm__ volatile("dsb sy" ::: "memory");

    gic_type = mmio_read32(GICD_BASE + GICD_TYPER);
    if ((gic_type & 0x1fu) == 0)
        return -3;

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
    return 0;
}

void arm64_timer_irq_cancel(void)
{
    timer_write_ctl(0);
    mmio_write32(GICD_BASE + GICD_ICENABLER,
                 1u << ARM64_PHYS_TIMER_PPI);
}

int arm64_timer_irq_arm_once(void)
{
    return timer_irq_prepare(1);
}

static int timer_irq_run(uint32_t target_ticks)
{
    uint64_t saved_daif;
    int result;

    result = timer_irq_prepare(target_ticks);
    if (result != 0)
        return result;
    __asm__ volatile("mrs %0, daif" : "=r"(saved_daif));
    __asm__ volatile("msr daifclr, #2");
    __asm__ volatile("isb");

    while (timer_ticks < timer_target_ticks && unexpected_irq == 0)
        __asm__ volatile("wfi");

    __asm__ volatile("msr daif, %0" :: "r"(saved_daif) : "memory");
    __asm__ volatile("isb");
    arm64_timer_irq_cancel();

    if (unexpected_irq != 0)
        return -4;
    if (timer_ticks != timer_target_ticks)
        return -5;
    return 0;
}

int arm64_timer_irq_fire_once(void)
{
    return timer_irq_run(1);
}

int arm64_timer_irq_smoke_test(void)
{
    int result = timer_irq_run(TIMER_TEST_TICKS);

    arm64_early_puts("CNTFRQ_EL0: ");
    arm64_early_puthex64(timer_frequency);
    arm64_early_puts(" timer ticks: ");
    arm64_early_puthex64(timer_ticks);
    arm64_early_puts("\n");

    if (result != 0)
        return result;

    arm64_early_puts("ARM64_TIMER_IRQ_OK\n");
    return 0;
}

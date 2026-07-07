/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/platform/raspi2/irq.c
 * Layer: ARM32 / Raspberry Pi 2 interrupt bring-up
 *
 * Responsibilities:
 * - Drive the BCM2836 ARM-local interrupt controller enough for the generic
 *   timer tick.
 * - Bridge the ARM-local "GPU/peripheral IRQ" source to the legacy BCM2835
 *   interrupt controller for the PL011 console UART.
 * - Keep the first Pi 2 milestone narrow: timer + UART only, no fake GIC.
 */

#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/interrupt.h>
#include <kernel/kprintf.h>
#include <kernel/smp.h>
#include <kernel/timer.h>
#include <kernel/types.h>
#include <kernel/uart.h>

#define LOCAL_CONTROL                  0x00u
#define LOCAL_GPU_IRQ_ROUTING          0x0Cu
#define LOCAL_CORE_TIMER_IRQ_CONTROL0  0x40u
#define LOCAL_CORE_IRQ_SOURCE0         0x60u

#define LOCAL_TIMER_IRQ_CNTPS          (1u << 0)
#define LOCAL_TIMER_IRQ_CNTPNS         (1u << 1)
#define LOCAL_TIMER_IRQ_PHYS_BITS      (LOCAL_TIMER_IRQ_CNTPS | LOCAL_TIMER_IRQ_CNTPNS)
#define LOCAL_IRQ_GPU                  (1u << 8)

#define LEGACY_IRQ_PENDING1            0x204u
#define LEGACY_IRQ_PENDING2            0x208u
#define LEGACY_ENABLE_IRQS1            0x210u
#define LEGACY_ENABLE_IRQS2            0x214u
#define LEGACY_DISABLE_IRQS1           0x21Cu
#define LEGACY_DISABLE_IRQS2           0x220u

#define RASPI2_IRQ_COUNTERS            64u

static volatile uint32_t raspi2_irq_total;
static volatile uint32_t raspi2_irq_last = 0xffffffffu;
static volatile uint32_t raspi2_irq_counts[RASPI2_IRQ_COUNTERS];

static inline volatile uint32_t* local_irq_base(void)
{
    if (!arch_mmu_enabled())
        return (volatile uint32_t*)(uintptr_t)arch_platform_irqctrl_phys_start();
    return (volatile uint32_t*)(uintptr_t)arch_platform_kernel_mmio_irqctrl_base();
}

static inline volatile uint32_t* legacy_irq_base(void)
{
    if (!arch_mmu_enabled())
        return (volatile uint32_t*)(uintptr_t)RASPI2_IRQCTRL_BASE;

    return (volatile uint32_t*)(uintptr_t)
        (arch_platform_kernel_mmio_irqctrl2_base() +
         (RASPI2_IRQCTRL_BASE - RASPI2_IRQCTRL_SECTION_BASE));
}

static inline uint32_t local_read(uint32_t offset)
{
    return *(volatile uint32_t*)((volatile uint8_t*)local_irq_base() + offset);
}

static inline void local_write(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t*)((volatile uint8_t*)local_irq_base() + offset) = value;
    arch_data_memory_barrier();
}

static inline uint32_t legacy_read(uint32_t offset)
{
    return *(volatile uint32_t*)((volatile uint8_t*)legacy_irq_base() + offset);
}

static inline void legacy_write(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t*)((volatile uint8_t*)legacy_irq_base() + offset) = value;
    arch_data_memory_barrier();
}

static void legacy_irq_enable(uint32_t irq)
{
    if (irq < 32) {
        legacy_write(LEGACY_ENABLE_IRQS1, 1u << irq);
    } else if (irq < 64) {
        legacy_write(LEGACY_ENABLE_IRQS2, 1u << (irq - 32));
    }
}

static void legacy_irq_disable(uint32_t irq)
{
    if (irq < 32) {
        legacy_write(LEGACY_DISABLE_IRQS1, 1u << irq);
    } else if (irq < 64) {
        legacy_write(LEGACY_DISABLE_IRQS2, 1u << (irq - 32));
    }
}

static bool legacy_irq_pending(uint32_t irq)
{
    if (irq < 32)
        return (legacy_read(LEGACY_IRQ_PENDING1) & (1u << irq)) != 0;
    if (irq < 64)
        return (legacy_read(LEGACY_IRQ_PENDING2) & (1u << (irq - 32))) != 0;
    return false;
}

static inline uint32_t core_timer_irq_control_offset(uint32_t cpu)
{
    return LOCAL_CORE_TIMER_IRQ_CONTROL0 + cpu * sizeof(uint32_t);
}

static inline uint32_t core_irq_source_offset(uint32_t cpu)
{
    return LOCAL_CORE_IRQ_SOURCE0 + cpu * sizeof(uint32_t);
}

static void raspi2_enable_local_timer_for_cpu(uint32_t cpu)
{
    if (cpu >= 4)
        return;

    /*
     * The physical generic timer can surface as secure or non-secure physical
     * depending on how firmware/QEMU entered the kernel. Enabling both keeps
     * the milestone portable while the handler accepts either source bit.
     */
    local_write(core_timer_irq_control_offset(cpu), LOCAL_TIMER_IRQ_PHYS_BITS);
}

void arch_irq_controller_init(void)
{
    for (uint32_t cpu = 0; cpu < 4; cpu++)
        local_write(core_timer_irq_control_offset(cpu), 0);

    /*
     * Route BCM2835 peripheral interrupts to core 0 as normal IRQs. QEMU's
     * raspi2b model and the real BCM2836 local controller both expose PL011 via
     * this "GPU IRQ" bridge rather than as a GIC SPI.
     */
    local_write(LOCAL_GPU_IRQ_ROUTING, 0);
    legacy_write(LEGACY_DISABLE_IRQS1, 0xffffffffu);
    legacy_write(LEGACY_DISABLE_IRQS2, 0xffffffffu);
    legacy_irq_enable(IRQ_UART);

    KBOOT_OKF("IRQ: BCM2836 local controller @ 0x%08X",
              (uint32_t)arch_platform_kernel_mmio_irqctrl_base());
}

void arch_irq_init_local_cpu_interface(void)
{
    raspi2_enable_local_timer_for_cpu(smp_processor_id());
}

const char* arch_irq_controller_name(void)
{
    return "BCM2836 local IRQ";
}

uint32_t arch_irq_controller_line_count(void)
{
    return RASPI2_IRQ_COUNTERS;
}

void arch_irq_enable(uint32_t irq)
{
    if (irq == IRQ_TIMER)
        raspi2_enable_local_timer_for_cpu(smp_processor_id());
    if (irq == IRQ_UART)
        legacy_irq_enable(irq);
}

void arch_irq_enable_level(uint32_t irq)
{
    arch_irq_enable(irq);
}

void arch_irq_disable(uint32_t irq)
{
    if (irq == IRQ_TIMER)
        local_write(core_timer_irq_control_offset(smp_processor_id()), 0);
    if (irq == IRQ_UART)
        legacy_irq_disable(irq);
}

void arch_irq_ack(uint32_t irq)
{
    (void)irq;
    /*
     * ARM-local timer sources are level-like: reprogramming CNTP_CVAL in
     * timer_irq_handler() deasserts the source. There is no GIC-style EOIR.
     */
}

uint32_t arch_irq_get_count(uint32_t irq)
{
    if (irq >= RASPI2_IRQ_COUNTERS)
        return 0;
    return raspi2_irq_counts[irq];
}

uint32_t arch_irq_get_total_count(void)
{
    return raspi2_irq_total;
}

uint32_t arch_irq_get_last_id(void)
{
    return raspi2_irq_last;
}

static bool raspi2_handle_legacy_irq(void)
{
    if (legacy_irq_pending(IRQ_UART)) {
        raspi2_irq_last = IRQ_UART;
        raspi2_irq_counts[IRQ_UART]++;
        uart_irq_handler();
        return true;
    }

    return false;
}

void arch_irq_send_ipi(uint32_t target_cpu_mask, uint32_t irq)
{
    (void)target_cpu_mask;
    (void)irq;
}

void arch_irq_send_ipi_others(uint32_t irq)
{
    (void)irq;
}

void irq_c_handler(void)
{
    uint32_t cpu = smp_processor_id();
    uint32_t source = cpu < 4 ? local_read(core_irq_source_offset(cpu)) : 0;

    raspi2_irq_total++;
    smp_note_irq(cpu);

    if (source & LOCAL_TIMER_IRQ_PHYS_BITS) {
        raspi2_irq_last = IRQ_TIMER;
        raspi2_irq_counts[IRQ_TIMER]++;
        timer_irq_handler();
        return;
    }

    if ((source & LOCAL_IRQ_GPU) && raspi2_handle_legacy_irq())
        return;

    raspi2_irq_last = source;
}

void fiq_c_handler(void)
{
    irq_c_handler();
}

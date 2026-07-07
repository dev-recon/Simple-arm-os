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
 * - Provide a safe IRQ facade while the BCM2836 interrupt controller is being
 *   ported.
 * - Make missing IRQ support explicit instead of accidentally touching GIC
 *   registers from the qemu-virt backend.
 */

#include <kernel/interrupt.h>
#include <kernel/kprintf.h>
#include <kernel/types.h>

static volatile uint32_t raspi2_irq_total;
static volatile uint32_t raspi2_irq_last = 0xffffffffu;

void arch_irq_controller_init(void)
{
    KBOOT_WARN("IRQ: BCM2836 controller not enabled yet");
}

void arch_irq_init_local_cpu_interface(void)
{
}

const char* arch_irq_controller_name(void)
{
    return "BCM2836 IRQ (stub)";
}

uint32_t arch_irq_controller_line_count(void)
{
    return 0;
}

void arch_irq_enable(uint32_t irq)
{
    (void)irq;
}

void arch_irq_enable_level(uint32_t irq)
{
    (void)irq;
}

void arch_irq_disable(uint32_t irq)
{
    (void)irq;
}

void arch_irq_ack(uint32_t irq)
{
    (void)irq;
}

uint32_t arch_irq_get_count(uint32_t irq)
{
    (void)irq;
    return 0;
}

uint32_t arch_irq_get_total_count(void)
{
    return raspi2_irq_total;
}

uint32_t arch_irq_get_last_id(void)
{
    return raspi2_irq_last;
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
    raspi2_irq_total++;
    raspi2_irq_last = 0xffffffffu;
}

void fiq_c_handler(void)
{
    irq_c_handler();
}

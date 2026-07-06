/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/interrupt.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_INTERRUPT_H
#define _KERNEL_INTERRUPT_H

#include <kernel/arch_platform.h>
#include <kernel/types.h>

/* Legacy generic IRQ aliases. The concrete IDs are supplied by the platform. */
#define IRQ_SGI_TLB_SHOOTDOWN VIRT_SGI_TLB_SHOOTDOWN_IRQ
#define IRQ_TIMER             VIRT_TIMER_NS_EL1_IRQ
#define IRQ_KEYBOARD          VIRT_UART_LEGACY_IRQ
#define IRQ_ATA               VIRT_ATA_LEGACY_IRQ

/* GIC functions */
void init_gic(void);
void gic_init_secondary_cpu_interface(void);
void gic_enable_irq_kernel(uint32_t irq);
void gic_ack_irq_kernel(uint32_t irq);
void enable_irq(uint32_t irq);
void enable_irq_level(uint32_t irq);
void disable_irq(uint32_t irq);
void clear_irq(uint32_t irq);

/* IRQ handler */
void irq_c_handler(void);
void fiq_c_handler(void);

/*
 * IRQ return-to-user slow path.
 *
 * The assembly IRQ handler calls irq_user_work_prepare() while still in IRQ
 * mode when the interrupted CPSR belongs to user mode. If it returns non-zero,
 * the handler abandons the IRQ frame, switches to SVC mode on the task kernel
 * stack, and calls irq_user_work_pending() before returning to user space from
 * the canonical task_context_t user snapshot.
 */
uint32_t irq_user_work_prepare(uint32_t* irq_frame);
void irq_user_work_pending(void);

uint32_t gic_get_irq_count(uint32_t irq);
uint32_t gic_get_total_irq_count(void);
uint32_t gic_get_last_irq_id(void);
void gic_send_sgi(uint32_t target_cpu_mask, uint32_t sgi_id);
void gic_send_sgi_others(uint32_t sgi_id);

static inline uint32_t irq_get_count(uint32_t irq)
{
    return gic_get_irq_count(irq);
}

static inline uint32_t irq_get_total_count(void)
{
    return gic_get_total_irq_count();
}

static inline uint32_t irq_get_last_id(void)
{
    return gic_get_last_irq_id();
}

static inline void irq_send_ipi(uint32_t target_cpu_mask, uint32_t irq)
{
    gic_send_sgi(target_cpu_mask, irq);
}

static inline void irq_send_ipi_others(uint32_t irq)
{
    gic_send_sgi_others(irq);
}

void complete_gic_debug(void);

#endif

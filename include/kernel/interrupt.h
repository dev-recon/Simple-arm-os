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

#include <kernel/types.h>

/* IRQ numbers */
#define IRQ_SGI_TLB_SHOOTDOWN 14
#define IRQ_TIMER           30
#define IRQ_KEYBOARD        33
#define IRQ_ATA             34

/* Adresses CORRECTES pour QEMU VExpress-A9 */
//#define GICD_BASE 0x1E001000  /* GIC Distributor - VExpress-A9 */
//#define GICC_BASE 0x1E000100  /* GIC CPU Interface - VExpress-A9 */

/* GIC functions */
void init_gic(void);
void gic_init_secondary_cpu_interface(void);
void enable_irq(uint32_t irq);
void enable_irq_level(uint32_t irq);
void disable_irq(uint32_t irq);
void clear_irq(uint32_t irq);

/* IRQ handler */
void irq_c_handler(void);
void fiq_c_handler(void);

uint32_t gic_get_irq_count(uint32_t irq);
uint32_t gic_get_total_irq_count(void);
uint32_t gic_get_last_irq_id(void);
void gic_send_sgi(uint32_t target_cpu_mask, uint32_t sgi_id);
void gic_send_sgi_others(uint32_t sgi_id);

void complete_gic_debug(void);

#endif

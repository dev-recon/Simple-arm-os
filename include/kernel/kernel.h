/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kernel.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_H
#define _KERNEL_H

#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/fdt.h>
#include <kernel/compiler.h>
#include <kernel/stddef.h>
#include <kernel/fd.h>
#include <kernel/linker.h>
#include <kernel/util.h>
#include <kernel/user_layout.h>
#include <kernel/address_space.h>

#define USE_RAMFS 1

/* === FONCTIONS KERNEL === */

/* Panic et debug */
void panic(const char* message) __attribute__((noreturn));

/* Initialisation precoce */
void init_early_uart(void);
uint32_t detect_memory(void);

/* Supprimer les declarations en conflit avec mmio.h */
/* GIC (Generic Interrupt Controller) */
void gic_init(void);
void gic_enable_irq_kernel(uint32_t irq);  /* Renamed pour eviter conflit */
void gic_disable_irq(uint32_t irq);
uint32_t gic_get_active_irq(void);
void gic_ack_irq_kernel(uint32_t irq);     /* Renamed pour eviter conflit */

/* ARM Generic Timer */
void timer_init(void);
uint64_t timer_get_count(void);
void timer_set_compare(uint64_t compare);
uint32_t timer_get_frequency(void);

/* VirtIO support */
bool virtio_probe_device(uint32_t device_id);
void virtio_init(void);

/* Device Tree support */
void* get_dtb_address(void);
bool parse_device_tree(void);
void print_cpu_mode(void);
//extern const uint32_t TASK_CONTEXT_OFF;

#endif /* _KERNEL_H */

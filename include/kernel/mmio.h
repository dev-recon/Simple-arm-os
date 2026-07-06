/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/mmio.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef MMIO_H
#define MMIO_H

#include <kernel/types.h>

/* Low-level MMIO helpers implemented by the active architecture backend. */
extern void PUT32(uint32_t address, uint32_t value);
extern uint32_t GET32(uint32_t address);
extern void PUT8(uint32_t address, uint32_t value);
extern uint32_t GET8(uint32_t address);
extern void PUT16(uint32_t address, uint32_t value);
extern uint32_t GET16(uint32_t address);

/* Typed wrappers for byte and halfword accesses. */
static inline void PUT8_MMIO(uint32_t address, uint8_t value) {
    PUT8(address, (unsigned int)value);
}

static inline uint8_t GET8_MMIO(uint32_t address) {
    return (uint8_t)GET8(address);
}

static inline void PUT16_MMIO(uint32_t address, uint16_t value) {
    PUT16(address, (unsigned int)value);
}

static inline uint16_t GET16_MMIO(uint32_t address) {
    return (uint16_t)GET16(address);
}

/* Versions avec barrieres renforcees */
extern void PUT32_STRONG(uint32_t address, uint32_t value);
extern uint32_t GET32_STRONG(uint32_t address);

/* Fonction de test MMIO */
extern uint32_t TEST_MMIO(uint32_t address);

/* Macros pour faciliter l'utilisation */
#define MMIO_WRITE32(addr, val)    PUT32((uint32_t)(addr), (uint32_t)(val))
#define MMIO_READ32(addr)          GET32((uint32_t)(addr))
#define MMIO_WRITE8(addr, val)     PUT8_MMIO((uint32_t)(addr), (uint8_t)(val))
#define MMIO_READ8(addr)           GET8_MMIO((uint32_t)(addr))

/* Test et debug */
#define TEST_REGISTER_WRITE(addr)  TEST_MMIO((uint32_t)(addr))

#endif /* MMIO_H */

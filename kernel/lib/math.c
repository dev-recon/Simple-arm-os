/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/lib/math.c
 * Layer: Kernel / support library
 *
 * Responsibilities:
 * - Provide freestanding helpers unavailable from libc.
 * - Keep formatting, string, math, and debug helpers deterministic.
 *
 * Notes:
 * - Must remain safe before userland and full runtime services exist.
 */

#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/kprintf.h>

static inline uint16_t safe_modulo(uint16_t dividend, uint16_t divisor)
{
    if (divisor == 0) return 0; // Protection division par zero
    
    // Methode 1: Soustraction repetee (s-re mais lente)
    uint16_t result = dividend;
    while (result >= divisor) {
        result -= divisor;
    }
    
    return result;
}

// Fonction de modulo optimisee pour les puissances de 2
uint16_t fast_modulo_power_of_2(uint16_t dividend, uint16_t divisor)
{
    // Verifier que divisor est une puissance de 2
    if (divisor != 0 && (divisor & (divisor - 1)) == 0) {
        // Pour les puissances de 2, modulo = AND avec (divisor - 1)
        return dividend & (divisor - 1);
    } else {
        // Fallback vers modulo s-r
        return safe_modulo(dividend, divisor);
    }
}

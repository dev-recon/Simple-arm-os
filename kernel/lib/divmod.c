/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/lib/divmod.c
 * Layer: Kernel / support library
 *
 * Responsibilities:
 * - Provide freestanding helpers unavailable from libc.
 * - Keep formatting, string, math, and debug helpers deterministic.
 *
 * Notes:
 * - Must remain safe before userland and full runtime services exist.
 */

unsigned int __aeabi_uidiv(unsigned int numerator, unsigned int denominator)
{
    unsigned int quotient = 0;
    
    if (denominator == 0) return 0;
    
    while (numerator >= denominator) {
        numerator -= denominator;
        quotient++;
    }
    
    return quotient;
}

unsigned int __aeabi_uidivmod(unsigned int numerator, unsigned int denominator)
{
    unsigned int quotient = __aeabi_uidiv(numerator, denominator);
    return numerator - (quotient * denominator);  /* reste */
}
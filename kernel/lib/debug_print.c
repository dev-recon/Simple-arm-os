/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/lib/debug_print.c
 * Layer: Kernel / support library
 *
 * Responsibilities:
 * - Provide freestanding helpers unavailable from libc.
 * - Keep formatting, string, math, and debug helpers deterministic.
 *
 * Notes:
 * - Must remain safe before userland and full runtime services exist.
 */

#include <kernel/types.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

/* Fonction simple qui fonctionne a coup s-r */
void debug_print_hex(const char* prefix, uint32_t value)
{
    KDEBUG("%s0x%x\n", prefix, value);
}

void debug_print_dec(const char* prefix, uint32_t value)
{
    KDEBUG("%s%d\n", prefix, value);
}

/* Version kprintf simple qui marche */
void simple_kprintf(const char* msg)
{
    KDEBUG("[SIMPLE] %s\n", msg);
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/timer/timer.c
 * Layer: ARM64 / architectural timer mechanism
 *
 * Responsibilities:
 * - Program the AArch64 EL1 physical timer compare register.
 * - Implement the architecture hook consumed by the common kernel timer.
 *
 * Notes:
 * - Tick policy, accounting and preemption remain in kernel/timer/timer.c.
 */

#include <asm/timer.h>
#include <kernel/types.h>

void timer_set_compare(uint64_t compare)
{
    set_cntp_cval(compare);
}

uint64_t timer_get_count(void)
{
    return get_cntpct();
}

uint32_t timer_get_frequency(void)
{
    return get_cntfrq();
}

/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/timer.h
 * Layer: ARM64 / CPU timer contract
 *
 * Responsibilities:
 * - Define the common scheduler tick rate for the ARM generic timer.
 * - Expose the selected platform frequency used before DTB discovery.
 *
 * Notes:
 * - Timer policy remains in the common kernel; this header describes only the
 *   architectural counter source consumed by that policy.
 */

#ifndef ASM_ARM64_TIMER_H
#define ASM_ARM64_TIMER_H

#include <asm/platform.h>
#include <kernel/types.h>

#define ARCH_TIMER_TICK_HZ     1000u
#define ARCH_TIMER_FALLBACK_HZ ARMOS_PLATFORM_TIMER_FALLBACK_HZ
#define CNTP_CTL_ENABLE        1u

static inline uint32_t get_cntfrq(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return (uint32_t)value;
}

static inline uint64_t get_cntpct(void)
{
    uint64_t value;

    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(value));
    return value;
}

static inline uint32_t get_cntp_ctl(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(value));
    return (uint32_t)value;
}

static inline void set_cntp_ctl(uint32_t control)
{
    __asm__ volatile("msr cntp_ctl_el0, %0\n\tisb" ::
                     "r"((uint64_t)control) : "memory");
}

static inline uint32_t get_cntp_tval(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, cntp_tval_el0" : "=r"(value));
    return (uint32_t)value;
}

static inline void set_cntp_tval(uint32_t value)
{
    __asm__ volatile("msr cntp_tval_el0, %0\n\tisb" ::
                     "r"((uint64_t)value) : "memory");
}

static inline void set_cntp_cval(uint64_t value)
{
    __asm__ volatile("msr cntp_cval_el0, %0\n\tisb" ::
                     "r"(value) : "memory");
}

#endif /* ASM_ARM64_TIMER_H */

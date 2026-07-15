/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/power/psci.c
 * Layer: ARM64 / PSCI power control
 *
 * Responsibilities:
 * - Enter PSCI SYSTEM_OFF for QEMU virt through the advertised HVC conduit.
 * - Keep AArch64 exception masking and barrier details out of generic power
 *   policy.
 *
 * Notes:
 * - The generic kernel owns shutdown ordering. If PSCI returns, this backend
 *   reports the failure and leaves the CPU halted with exceptions masked.
 */

#include <kernel/arch_power.h>
#include <kernel/kprintf.h>
#include <kernel/types.h>

#define PSCI_0_2_FN_SYSTEM_OFF 0x84000008u

void arch_system_off(void)
{
    register uint64_t function_id __asm__("x0") = PSCI_0_2_FN_SYSTEM_OFF;

    __asm__ volatile(
        "msr daifset, #0xf\n"
        "dsb sy\n"
        "isb\n"
        "hvc #0"
        : "+r"(function_id)
        :
        : "memory");

    KERROR("PSCI SYSTEM_OFF returned unexpectedly\n");
    for (;;)
        __asm__ volatile("wfe");
}

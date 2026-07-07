/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/platform/raspi2/power.c
 * Layer: ARM32 / Raspberry Pi 2 power control
 *
 * Responsibilities:
 * - Stop cleanly when the generic shutdown path reaches the final platform
 *   hook.
 *
 * Notes:
 * - Real Raspberry Pi power-off/reset should eventually go through the
 *   VideoCore mailbox/property interface. Until then, halt instead of issuing
 *   qemu-virt PSCI calls.
 */

#include <kernel/arch_power.h>
#include <kernel/kprintf.h>
#include <asm/arm.h>

void arch_system_off(void)
{
    (void)arm_disable_irq_fiq_save();
    KERROR("raspi2: system-off mailbox not implemented, halting CPU\n");
    for (;;) {
        wait_for_interrupt();
    }
}

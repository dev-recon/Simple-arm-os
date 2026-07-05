/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/power/psci.c
 * Layer: ARM32 / PSCI power control
 *
 * Responsibilities:
 * - Enter PSCI SYSTEM_OFF for QEMU virt and PSCI-capable ARMv7 platforms.
 * - Keep HVC and ARM barrier details out of the generic shutdown path.
 *
 * Notes:
 * - If PSCI returns, the machine did not power off; stay halted with IRQ/FIQ
 *   masked so the failure is visible on tty0.
 */

#include <kernel/arch_power.h>
#include <kernel/kprintf.h>
#include <kernel/types.h>
#include <asm/arm.h>

#define PSCI_0_2_FN_SYSTEM_OFF 0x84000008u

void arch_system_off(void)
{
    uint32_t function_id;

    (void)arm_disable_irq_fiq_save();
    data_sync_barrier();
    instruction_sync_barrier();

    function_id = arm_hvc_call(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
    KERROR("PSCI SYSTEM_OFF returned: 0x%08X\n", function_id);
    for (;;) {
        wait_for_interrupt();
    }
}

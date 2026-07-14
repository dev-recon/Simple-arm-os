/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/cpu/cpu.c
 * Layer: ARM32 / CPU identity
 *
 * Responsibilities:
 * - Read ARMv7 CPU identity registers for procfs and diagnostics.
 * - Keep ARM CP15 register access out of generic procfs code.
 */

#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/string.h>
#include <asm/arm.h>

void arch_get_cpuinfo(arch_cpuinfo_t* info)
{
    uint32_t midr;

    if (!info)
        return;

    memset(info, 0, sizeof(*info));

    midr = arm_read_midr();
    info->model_name = arch_platform_cpu_model();
    info->features = arch_platform_cpu_features();
    info->hardware = arch_platform_hardware_name();
    info->implementer = (midr >> 24) & 0xff;
    info->architecture = 7;
    info->part = (midr >> 4) & 0xfff;
    info->revision = midr & 0xf;
    info->mpidr = arm_read_mpidr();
}

const char* arch_machine_name(void)
{
    return "armv7l";
}

void arch_disable_interrupts(void)
{
    disable_interrupts();
}

void arch_enable_interrupts(void)
{
    enable_interrupts();
}

void arch_enable_async_abort(void)
{
    enable_async_abort();
}

void arch_enable_smp_coherency(void)
{
    arm_enable_smp_coherency();
}

void arch_wait_for_interrupt(void)
{
    wait_for_interrupt();
}

void arch_disable_branch_predictor(void)
{
    uint32_t sctlr;

    sctlr = get_sctlr();
    sctlr &= ~(1u << 11);
    set_sctlr(sctlr);
    flush_branch_predictor();
}

uint32_t arch_timer_frequency(void)
{
    return arch_platform_timer_effective_hz(get_cntfrq());
}

uint64_t arch_timer_counter(void)
{
    return get_cntpct();
}

bool arch_mmu_enabled(void)
{
    return (get_sctlr() & SCTLR_M) != 0;
}

vaddr_t arch_current_link_register(void)
{
    return arm_current_lr();
}

vaddr_t arch_current_stack_pointer(void)
{
    return arm_current_sp();
}

void arch_set_stack_pointer(vaddr_t sp)
{
    arm_set_sp(sp);
}

uint32_t arch_current_mode(void)
{
    return get_cpsr() & ARM_CPSR_MODE;
}

bool arch_current_mode_is_interrupt(void)
{
    return arch_current_mode() == ARM_MODE_IRQ;
}

uint32_t arch_saved_mode(void)
{
    return read_spsr() & ARM_CPSR_MODE;
}

uint32_t arch_saved_svc_status(void)
{
    return read_spsr_svc();
}

bool arch_mode_is_user(uint32_t mode)
{
    return mode == ARM_MODE_USR;
}

bool arch_mode_is_supervisor(uint32_t mode)
{
    return mode == ARM_MODE_SVC;
}

const char* arch_mode_name(uint32_t mode)
{
    switch (mode) {
    case ARM_MODE_USR:
        return "USR";
    case ARM_MODE_SVC:
        return "SVC";
    case ARM_MODE_IRQ:
        return "IRQ";
    case ARM_MODE_FIQ:
        return "FIQ";
    case ARM_MODE_ABT:
        return "ABT";
    case ARM_MODE_UND:
        return "UND";
    case ARM_MODE_SYS:
        return "SYS";
    default:
        return "UNKNOWN";
    }
}

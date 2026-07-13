/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/include/asm/exception.h
 * Layer: ARM64 / exception interface
 *
 * Responsibilities:
 * - Register the active bootstrap EL0 VM and saved register context.
 * - Expose syscall smoke-test results to the platform bring-up code.
 *
 * Notes:
 * - This interface remains bootstrap-only until task ownership is available.
 */

#ifndef ARMOS_ARM64_EXCEPTION_H
#define ARMOS_ARM64_EXCEPTION_H

#include <asm/user_vm.h>
#include <asm/user_context.h>

typedef unsigned long long arm64_exception_u64;

void arm64_exception_set_el0_context(const arm64_user_vm_t *vm,
                                     arm64_user_context_t *registers,
                                     arm64_exception_u64 exit_address);
unsigned int arm64_exception_el0_syscall_count(void);
arm64_exception_u64 arm64_exception_el0_exit_status(void);

#endif

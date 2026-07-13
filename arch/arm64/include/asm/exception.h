/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_EXCEPTION_H
#define ARMOS_ARM64_EXCEPTION_H

#include <asm/user_vm.h>

typedef unsigned long long arm64_exception_u64;

void arm64_exception_set_el0_context(const arm64_user_vm_t *vm,
                                     arm64_exception_u64 exit_address);
unsigned int arm64_exception_el0_syscall_count(void);
arm64_exception_u64 arm64_exception_el0_exit_status(void);

#endif

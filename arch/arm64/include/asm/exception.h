/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_EXCEPTION_H
#define ARMOS_ARM64_EXCEPTION_H

typedef unsigned long long arm64_exception_u64;

void arm64_exception_set_el0_exit(arm64_exception_u64 address);
unsigned int arm64_exception_el0_svc_count(void);

#endif

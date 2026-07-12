/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ARMOS_ARM64_IRQ_H
#define ARMOS_ARM64_IRQ_H

void arm64_irq_dispatch(void);
int arm64_timer_irq_smoke_test(void);

#endif

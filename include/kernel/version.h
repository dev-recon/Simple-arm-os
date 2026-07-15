/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/version.h
 * Layer: Kernel / release identity
 *
 * Responsibilities:
 * - Expose the ArmOS release configured by the build system.
 * - Provide consistent strings for boot and system-identification paths.
 *
 * Notes:
 * - ARMOS_VERSION is defined once in the top-level Makefile.
 * - Changing that value updates the kernel banner, uname and os.conf.
 */

#ifndef _KERNEL_VERSION_H
#define _KERNEL_VERSION_H

#ifndef ARMOS_VERSION
#error "ARMOS_VERSION must be defined by the build system"
#endif

#define ARMOS_NAME "ArmOS"
#define ARMOS_VERSION_BANNER ARMOS_NAME " " ARMOS_VERSION

#endif /* _KERNEL_VERSION_H */

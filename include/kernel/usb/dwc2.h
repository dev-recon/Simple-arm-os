/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/usb/dwc2.h
 * Layer: Kernel / USB host controllers
 *
 * Responsibilities:
 * - Register a DesignWare USB 2.0 host controller with the generic USB core.
 * - Keep BCM2837 controller details outside platform and USB-core code.
 */

#ifndef _KERNEL_USB_DWC2_H
#define _KERNEL_USB_DWC2_H

int dwc2_usb_register(int tty_id);

#endif /* _KERNEL_USB_DWC2_H */

/*
 * Minimal NetBSD tools-build compatibility header for ArmOS.
 *
 * NetBSD nawk includes nbtool_config.h when it is built as a host tool.  ArmOS
 * builds the same upstream sources directly, so keep the compatibility knobs
 * local instead of editing vendored files.
 */

#ifndef ARMOS_BSDAWK_NBTOOL_CONFIG_H
#define ARMOS_BSDAWK_NBTOOL_CONFIG_H

#include "armos_compat.h"

#endif

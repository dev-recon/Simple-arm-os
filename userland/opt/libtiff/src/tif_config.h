/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/opt/libtiff/src/tif_config.h
 * Layer: Userland / third-party configuration
 *
 * Responsibilities:
 * - Configure the private libtiff feature surface used by ArmOS.
 * - Derive ABI properties from the active cross-compiler target.
 */

#ifndef TIF_CONFIG_H
#define TIF_CONFIG_H

#include "tiffconf.h"

#define CCITT_SUPPORT 1
#define CHECK_JPEG_YCBCR_SUBSAMPLING 1
#define HAVE_ASSERT_H 1
#define HAVE_FCNTL_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define JPEG_SUPPORT 1
#define PACKAGE "tiff"
#define PACKAGE_BUGREPORT "https://gitlab.com/libtiff/libtiff"
#define PACKAGE_NAME "LibTIFF"
#define PACKAGE_TARNAME "tiff"
#define PACKAGE_URL "https://libtiff.gitlab.io/libtiff/"
#define SIZEOF_SIZE_T __SIZEOF_SIZE_T__
#define STRIP_SIZE_DEFAULT 8192
#define TIFF_MAX_DIR_COUNT 1048576
#define WORDS_BIGENDIAN 0

#define TIFF_SIZE_FORMAT "zu"
#define TIFF_SSIZE_FORMAT "td"

#endif /* TIF_CONFIG_H */

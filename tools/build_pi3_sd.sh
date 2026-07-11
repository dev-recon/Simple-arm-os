#!/usr/bin/env bash
# build_pi3_sd.sh - build Raspberry Pi 3 AArch32 images and stage them to SD.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export TARGET_ARCH="${TARGET_ARCH:-arm32}"
export TARGET_PLATFORM="${TARGET_PLATFORM:-pi3}"
export DEVICE_TREE="${DEVICE_TREE:-bcm2710-rpi-3-b-plus.dtb}"
export DTOVERLAY="${DTOVERLAY:-disable-bt}"

exec "$SCRIPT_DIR/build_pi2_sd.sh" "$@"

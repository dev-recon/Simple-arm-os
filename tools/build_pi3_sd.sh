#!/usr/bin/env bash
# Compatibility wrapper for the default ARM64 Raspberry Pi 3 target.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export TARGET_ARCH="${TARGET_ARCH:-arm64}"
export TARGET_PLATFORM="${TARGET_PLATFORM:-raspi3}"
export SD_VOLUME="${SD_VOLUME:-/Volumes/PI2}"
export DEVICE_TREE="${DEVICE_TREE:-bcm2710-rpi-3-b-plus.dtb}"
export DTOVERLAY="${DTOVERLAY:-disable-bt}"

exec "$SCRIPT_DIR/build_raspberry_sd.sh" "$@"

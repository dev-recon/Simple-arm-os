#!/usr/bin/env bash
# Compatibility wrapper for the ARM32 Raspberry Pi 2 target.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export TARGET_ARCH="${TARGET_ARCH:-arm32}"
export TARGET_PLATFORM="${TARGET_PLATFORM:-raspi2}"
export SD_VOLUME="${SD_VOLUME:-/Volumes/PI2}"

exec "$SCRIPT_DIR/build_raspberry_sd.sh" "$@"

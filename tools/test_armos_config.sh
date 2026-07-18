#!/usr/bin/env bash
# Smoke tests for the ArmOS configuration precedence and validation rules.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TMP_CONFIG="$(mktemp -t armos-config-test.XXXXXX)"
trap 'rm -f "$TMP_CONFIG"' EXIT

printf '%s\n' \
    'TARGET_ARCH=arm64' \
    'TARGET_PLATFORM=qemu-virt' \
    'ENABLE_NET=yes' \
    'ENABLE_ILI9341=no' \
    'BUILD_NCURSES=yes' \
    'BUILD_NANO=yes' > "$TMP_CONFIG"

resolved="$(ARMOS_CONFIG="$TMP_CONFIG" bash -c '
    ROOT_DIR="$1"
    source "$1/tools/armos_config.sh"
    armos_config_validate "$1"
    printf "%s/%s net=%s ili9341=%s nano=%s\n" \
        "$TARGET_ARCH" "$TARGET_PLATFORM" "$ENABLE_NET" \
        "$ENABLE_ILI9341" "$BUILD_NANO"
' _ "$ROOT_DIR")"
[ "$resolved" = 'arm64/qemu-virt net=1 ili9341=0 nano=1' ]

resolved="$(TARGET_ARCH=arm32 ARMOS_CONFIG="$TMP_CONFIG" bash -c '
    ROOT_DIR="$1"
    source "$1/tools/armos_config.sh"
    printf "%s/%s\n" "$TARGET_ARCH" "$TARGET_PLATFORM"
' _ "$ROOT_DIR")"
[ "$resolved" = 'arm32/qemu-virt' ]

printf 'UNKNOWN_OPTION=yes\n' > "$TMP_CONFIG"
if ARMOS_CONFIG="$TMP_CONFIG" "$ROOT_DIR/tools/armos_config.sh" --show >/dev/null 2>&1; then
    echo "configuration accepted an unknown key" >&2
    exit 1
fi
if ARMOS_CONFIG="$TMP_CONFIG" make -s -C "$ROOT_DIR" config >/dev/null 2>&1; then
    echo "make accepted an unknown configuration key" >&2
    exit 1
fi

echo ARMOS_CONFIG_TEST_OK

#!/usr/bin/env bash
# build-kernel.sh - rebuild only the ArmOS kernel.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# shellcheck source=tools/armos_config.sh
source "$ROOT_DIR/tools/armos_config.sh"

TARGET_ARCH="${TARGET_ARCH:-arm32}"
TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"
if [ "$TARGET_ARCH" = arm64 ]; then
    ARCH="${ARCH:-${CROSS_COMPILE:-aarch64-elf-}}"
else
    ARCH="${ARCH:-${CROSS_COMPILE:-arm-none-eabi-}}"
fi
armos_config_validate "$ROOT_DIR"

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

cd "$ROOT_DIR"

echo "=== BUILD ARMOS KERNEL ==="
echo "Target: ${TARGET_ARCH}/${TARGET_PLATFORM}"

for tool in make "${ARCH}gcc" "${ARCH}ld" "${ARCH}objcopy" "${ARCH}objdump"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

echo "=== Cleaning kernel build ==="
make clean ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

make platform-kernel ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

echo "=== KERNEL BUILD DONE ==="
echo "Kernel image: build/images/kernel-${TARGET_PLATFORM}.bin"
echo "Boot existing disk with: ./boot.sh"

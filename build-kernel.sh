#!/usr/bin/env bash
# build-kernel.sh - rebuild only the ArmOS kernel.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"
TARGET_ARCH="${TARGET_ARCH:-arm32}"
TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"

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

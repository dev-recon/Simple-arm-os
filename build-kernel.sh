#!/usr/bin/env bash
# build-kernel.sh - rebuild only the ArmOS kernel.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

cd "$ROOT_DIR"

echo "=== BUILD ARMOS KERNEL ==="

for tool in make "${ARCH}gcc" "${ARCH}ld" "${ARCH}objcopy" "${ARCH}objdump"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

echo "=== Cleaning kernel build ==="
make clean ARCH="$ARCH" CROSS_COMPILE="$ARCH"

make kernel.bin ARCH="$ARCH" CROSS_COMPILE="$ARCH"

echo "=== KERNEL BUILD DONE ==="
echo "Boot existing disk with: ./boot.sh"

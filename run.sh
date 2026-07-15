#!/usr/bin/env bash
# run.sh - build the selected ArmOS target, then launch it with QEMU.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The fresh-machine development route intentionally stays on the most stable
# kernel-feature reference. Hardware and ARM64 targets remain explicit opt-in
# combinations through the same build pipeline.
export TARGET_ARCH="${TARGET_ARCH:-arm32}"
export TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"

cd "$ROOT_DIR"

echo "=== RUN ARMOS ==="
echo "Target: ${TARGET_ARCH}/${TARGET_PLATFORM}"

"$ROOT_DIR/build.sh"
exec "$ROOT_DIR/boot.sh" "$@"

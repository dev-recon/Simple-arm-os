#!/usr/bin/env bash
# run.sh - build the selected ArmOS target, then launch it with QEMU.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# shellcheck source=tools/armos_config.sh
source "$ROOT_DIR/tools/armos_config.sh"

# The fresh-machine development route intentionally stays on the most stable
# kernel-feature reference. Hardware and ARM64 targets remain explicit opt-in
# combinations through the same build pipeline.
export TARGET_ARCH="${TARGET_ARCH:-arm32}"
export TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"
export ENABLE_NET="${ENABLE_NET:-0}"
export ENABLE_GPU="${ENABLE_GPU:-0}"
armos_config_validate "$ROOT_DIR"

cd "$ROOT_DIR"

echo "=== RUN ARMOS ==="
echo "Target: ${TARGET_ARCH}/${TARGET_PLATFORM}"

"$ROOT_DIR/build.sh"
exec "$ROOT_DIR/boot.sh" "$@"

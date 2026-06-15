#!/bin/bash
# boot.sh - boot an existing kernel.bin + disk.img without rebuilding.

set -euo pipefail

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

if [ ! -f kernel.bin ]; then
    echo "Error: kernel.bin not found. Run ./run.sh first to build everything."
    exit 1
fi

if [ ! -f disk.img ]; then
    echo "Error: disk.img not found. Run ./run.sh first to create the disk image."
    exit 1
fi

if ! command -v qemu-system-arm >/dev/null 2>&1; then
    echo "Error: qemu-system-arm not found in PATH"
    exit 1
fi

echo "=== Booting existing kernel.bin + disk.img ==="
qemu-system-arm -M virt -cpu cortex-a15 \
    -m 2G -smp 1 \
    -drive file=disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -kernel kernel.bin \
    -nographic

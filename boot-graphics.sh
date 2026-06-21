#!/bin/bash
# boot-graphics.sh - boot an existing kernel.bin + disk.img with a QEMU
# graphics window for framebuffer/GPU experiments.
#
# ArmOS still uses the PL011 UART console today. This script keeps that UART on
# stdio for normal shell interaction, and also exposes a virtio-gpu display
# window that future framebuffer work can target.

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

echo "=== Booting existing kernel.bin + disk.img with virtio-gpu ==="
echo "UART console stays on this terminal; graphics output opens in a QEMU window."
qemu-system-arm -M virt -cpu cortex-a15 \
    -m 2G -smp 1 \
    -drive file=disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -device virtio-gpu-device \
    -device virtio-keyboard-device,event_idx=off,indirect_desc=off \
    -chardev stdio,id=uart0,signal=off \
    -serial chardev:uart0 \
    -monitor none \
    -kernel kernel.bin \
    -display cocoa,show-cursor=on

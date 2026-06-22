#!/bin/bash
# boot.sh - boot an existing kernel.bin + disk.img without rebuilding.

set -euo pipefail

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

select_qemu() {
    if [ -n "${1:-}" ]; then
        printf '%s\n' "$1"
    elif [ -n "${QEMU:-}" ]; then
        printf '%s\n' "$QEMU"
    elif [ -x /opt/homebrew/bin/qemu-system-arm ]; then
        printf '%s\n' /opt/homebrew/bin/qemu-system-arm
    elif [ -x /usr/local/bin/qemu-system-arm ]; then
        printf '%s\n' /usr/local/bin/qemu-system-arm
    else
        printf '%s\n' qemu-system-arm
    fi
}

QEMU="$(select_qemu "${1:-}")"

if [ ! -f kernel.bin ]; then
    echo "Error: kernel.bin not found. Run ./run.sh first to build everything."
    exit 1
fi

if [ ! -f disk.img ]; then
    echo "Error: disk.img not found. Run ./run.sh first to create the disk image."
    exit 1
fi

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "Error: QEMU binary '$QEMU' not found"
    exit 1
fi

echo "=== Booting existing kernel.bin + disk.img ==="
echo "QEMU: $("$QEMU" --version | head -n 1)"
"$QEMU" -M virt -cpu cortex-a15 \
    -m 2G -smp 1 \
    -drive file=disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -kernel kernel.bin \
    -nographic

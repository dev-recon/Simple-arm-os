#!/bin/bash
# boot-graphics.sh - boot an existing kernel.bin + disk.img with a QEMU
# graphics window for framebuffer/GPU experiments.
#
# This script keeps the PL011 UART console on stdio as tty0 and opens a
# virtio-gpu window used by tty1. tty0 is the rescue console and must remain
# usable even if graphical console work regresses.

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

select_display() {
    if [ -n "${QEMU_DISPLAY:-}" ]; then
        printf '%s\n' "$QEMU_DISPLAY"
        return
    fi

    case "$(uname -s)" in
        Darwin)
            printf '%s\n' "cocoa,show-cursor=on"
            ;;
        Linux)
            if "$QEMU" -display help 2>/dev/null | grep -q '^gtk\b'; then
                printf '%s\n' "gtk,show-cursor=on"
            elif "$QEMU" -display help 2>/dev/null | grep -q '^sdl\b'; then
                printf '%s\n' "sdl,show-cursor=on"
            else
                printf '%s\n' "default"
            fi
            ;;
        *)
            printf '%s\n' "default"
            ;;
    esac
}

QEMU="$(select_qemu "${1:-}")"
QEMU_DISPLAY="$(select_display)"
SMP_CPUS="${SMP_CPUS:-1}"

GPU_DEVICE="virtio-gpu-device"
if [ -n "${GPU_XRES:-}" ] || [ -n "${GPU_YRES:-}" ]; then
    GPU_XRES="${GPU_XRES:-1024}"
    GPU_YRES="${GPU_YRES:-768}"
    GPU_DEVICE="${GPU_DEVICE},xres=${GPU_XRES},yres=${GPU_YRES}"
fi

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

echo "=== Booting existing kernel.bin + disk.img with virtio-gpu ==="
echo "UART console stays on this terminal; graphics output opens in a QEMU window."
echo "QEMU: $("$QEMU" --version | head -n 1)"
echo "GPU: ${GPU_DEVICE}, display=${QEMU_DISPLAY}"
echo "SMP: ${SMP_CPUS} CPU(s)"
"$QEMU" -M virt -cpu cortex-a15 \
    -m 2G -smp "${SMP_CPUS}" \
    -drive file=disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -device "${GPU_DEVICE}" \
    -device virtio-keyboard-device,event_idx=off,indirect_desc=off \
    -chardev stdio,id=uart0,signal=off \
    -serial chardev:uart0 \
    -monitor none \
    -kernel kernel.bin \
    -display "${QEMU_DISPLAY}"

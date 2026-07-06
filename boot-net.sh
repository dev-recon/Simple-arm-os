#!/bin/bash
# boot-net.sh - boot an existing kernel.bin + disk.img with virtio-net.
#
# This variant deliberately stays in nographic/UART mode. tty0 remains the
# rescue console while network bring-up is experimental.

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
. "$ROOT_DIR/tools/qemu_platform_env.sh"
SMP_CPUS="${SMP_CPUS:-1}"

NET_HOST_ADDR="${NET_HOST_ADDR:-127.0.0.1}"
NET_HOST_PORT="${NET_HOST_PORT:-2323}"
NET_GUEST_PORT="${NET_GUEST_PORT:-2323}"
NET_MAC="${NET_MAC:-52:54:00:12:34:56}"
NETDEV="user,id=net0,hostfwd=tcp:${NET_HOST_ADDR}:${NET_HOST_PORT}-:${NET_GUEST_PORT}"
NET_DEVICE="${QEMU_NET_DEVICE_MODEL},netdev=net0,mac=${NET_MAC}"

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

echo "=== Booting existing kernel.bin + disk.img with virtio-net ==="
echo "UART console stays on this terminal; graphics are disabled."
echo "QEMU: $("$QEMU" --version | head -n 1)"
echo "Platform: ${TARGET_ARCH}/${TARGET_PLATFORM}"
echo "Machine: ${QEMU_MACHINE}, CPU: ${QEMU_CPU}"
echo "NET: ${NET_DEVICE}"
echo "FWD: ${NET_HOST_ADDR}:${NET_HOST_PORT} -> guest :${NET_GUEST_PORT}"
echo "SMP: ${SMP_CPUS} CPU(s)"
"$QEMU" -M "${QEMU_MACHINE}" -cpu "${QEMU_CPU}" \
    -m 2G -smp "${SMP_CPUS}" \
    -drive file=disk.img,if=none,format=raw,id=hd0 \
    -device "${QEMU_BLOCK_DEVICE}" \
    -netdev "${NETDEV}" \
    -device "${NET_DEVICE}" \
    -kernel kernel.bin \
    -nographic

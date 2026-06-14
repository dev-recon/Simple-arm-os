#!/bin/bash
# run.sh - rebuild userland, recreate the FAT image, then boot the kernel.

set -euo pipefail

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

USERFS_DIR="userfs"
USERLAND_DIR="userland"
LIBC_DIR="libc"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== RUN KERNEL SCRIPT ==="

cd "$ROOT_DIR"

for dir in "$USERFS_DIR" "$USERLAND_DIR" "$LIBC_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Error: $dir directory not found!"
        exit 1
    fi
done

for tool in make arm-none-eabi-gcc arm-none-eabi-ld arm-none-eabi-objcopy arm-none-eabi-objdump mkfs.fat mcopy mmd qemu-system-arm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH"
        exit 1
    fi
done

echo "=== Rebuilding libc ==="
make -C "$LIBC_DIR" distclean
make -C "$LIBC_DIR" install

echo "=== Rebuilding userland ==="
make -C "$USERLAND_DIR" clean
make -C "$USERLAND_DIR" install

echo "=== Rebuilding kernel ==="
make kernel.bin

echo "=== Recreating disk image ==="
rm -f disk.img
make disk.img

echo "=== Booting QEMU ==="
make run-userfs

#!/bin/bash
# run.sh - rebuild userland, recreate the FAT image, then boot the kernel.

set -euo pipefail

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

if [ -d /opt/homebrew/opt/e2fsprogs/sbin ]; then
    export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
fi
if [ -d /usr/local/opt/e2fsprogs/sbin ]; then
    export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
fi

USERFS_DIR="userfs"
USERLAND_DIR="userland"
LIBC_DIR="libc"
BUILD_NEWLIB="${BUILD_NEWLIB:-0}"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_NEWLIB_SYSROOT="$ROOT_DIR/build/newlib-sysroot/arm-none-eabi"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$DEFAULT_NEWLIB_SYSROOT}"

echo "=== RUN KERNEL SCRIPT ==="

cd "$ROOT_DIR"

for dir in "$USERFS_DIR" "$USERLAND_DIR" "$LIBC_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Error: $dir directory not found!"
        exit 1
    fi
done

for tool in make arm-none-eabi-gcc arm-none-eabi-ld arm-none-eabi-objcopy arm-none-eabi-objdump mkfs.fat mcopy mmd mke2fs debugfs qemu-system-arm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH"
        exit 1
    fi
done

echo "=== Rebuilding libc ==="
make -C "$LIBC_DIR" distclean
make -C "$LIBC_DIR" install

if [ "$BUILD_NEWLIB" = "1" ]; then
    if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_SYSROOT/lib/libc.a" ]; then
        echo "=== Building repo-local newlib sysroot ==="
        NEWLIB_INSTALL_ROOT="$ROOT_DIR/build/newlib-sysroot" ./tools/build_newlib.sh
    fi
fi

echo "=== Rebuilding userland ==="
make -C "$USERLAND_DIR" clean
make -C "$USERLAND_DIR" install BUILD_NEWLIB="$BUILD_NEWLIB" NEWLIB_SYSROOT="$NEWLIB_SYSROOT"

echo "=== Rebuilding kernel ==="
make kernel.bin

echo "=== Recreating disk image ==="
rm -f disk.img fat32.img ext2.img
make disk.img

echo "=== Booting QEMU ==="
make run-userfs

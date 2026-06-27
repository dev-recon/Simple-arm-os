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
BUILD_NEWLIB="${BUILD_NEWLIB:-1}"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_NEWLIB_SYSROOT="$ROOT_DIR/build/newlib-sysroot/arm-none-eabi"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$DEFAULT_NEWLIB_SYSROOT}"

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

echo "=== RUN KERNEL SCRIPT ==="

cd "$ROOT_DIR"

for dir in "$USERFS_DIR" "$USERLAND_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Error: $dir directory not found!"
        exit 1
    fi
done

for tool in make python3 arm-none-eabi-gcc arm-none-eabi-ld arm-none-eabi-objcopy arm-none-eabi-objdump mkfs.fat mcopy mmd mke2fs debugfs; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH"
        exit 1
    fi
done

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "Error: QEMU binary '$QEMU' not found"
    exit 1
fi

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
echo "QEMU: $("$QEMU" --version | head -n 1)"
make run-userfs QEMU="$QEMU"

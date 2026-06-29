#!/usr/bin/env bash
# build.sh - rebuild ArmOS without launching QEMU.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"
BUILD_NEWLIB="${BUILD_NEWLIB:-1}"
BUILD_TCC="${BUILD_TCC:-1}"
DEFAULT_NEWLIB_SYSROOT="$ROOT_DIR/build/newlib-sysroot/arm-none-eabi"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$DEFAULT_NEWLIB_SYSROOT}"

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

if [ -d /opt/homebrew/opt/e2fsprogs/sbin ]; then
    export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
fi
if [ -d /usr/local/opt/e2fsprogs/sbin ]; then
    export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
fi

cd "$ROOT_DIR"

echo "=== BUILD ARMOS ==="

for dir in userfs userland kernel newlib-port; do
    if [ ! -d "$dir" ]; then
        echo "Error: $dir directory not found" >&2
        exit 1
    fi
done

for tool in make python3 "${ARCH}gcc" "${ARCH}ld" "${ARCH}objcopy" "${ARCH}objdump" mkfs.fat mcopy mmd mke2fs debugfs; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

if [ "$BUILD_NEWLIB" = "1" ]; then
    if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_SYSROOT/lib/libc.a" ]; then
        echo "=== Building repo-local newlib sysroot ==="
        ARCH="$ARCH" NEWLIB_INSTALL_ROOT="$ROOT_DIR/build/newlib-sysroot" ./tools/build_newlib.sh
    fi
fi

echo "=== Rebuilding userland ==="
make -C userland clean
make -C userland install \
    BUILD_NEWLIB="$BUILD_NEWLIB" \
    ENABLE_TCC="$BUILD_TCC" \
    ARCH="$ARCH" \
    NEWLIB_SYSROOT="$NEWLIB_SYSROOT" \
    NEWLIB_LIBC="$NEWLIB_SYSROOT/lib/libc.a"

if [ "$BUILD_TCC" = "1" ]; then
    echo "=== Building native TinyCC bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_tcc_native.sh
    rsync -a build/tcc-native/bundle/opt/tcc/ userfs/opt/tcc/
fi

echo "=== Rebuilding kernel ==="
make kernel.bin ARCH="$ARCH" CROSS_COMPILE="$ARCH"

echo "=== Recreating disk image ==="
rm -f disk.img fat32.img ext2.img
make disk.img ARCH="$ARCH" CROSS_COMPILE="$ARCH"

echo "=== BUILD DONE ==="
echo "Boot existing build with: ./boot.sh"
echo "Rebuild and boot with:    ./run.sh"

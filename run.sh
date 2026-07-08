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
BUILD_TCC="${BUILD_TCC:-1}"
BUILD_BSD="${BUILD_BSD:-0}"
TARGET_ARCH="${TARGET_ARCH:-arm32}"
TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"
ARCH="${ARCH:-arm-none-eabi-}"

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
echo "Target: ${TARGET_ARCH}/${TARGET_PLATFORM}"

cd "$ROOT_DIR"

for dir in "$USERFS_DIR" "$USERLAND_DIR"; do
    if [ ! -d "$dir" ]; then
        echo "Error: $dir directory not found!"
        exit 1
    fi
done

for tool in make python3 "${ARCH}gcc" "${ARCH}ld" "${ARCH}objcopy" "${ARCH}objdump" mkfs.fat mcopy mmd mke2fs debugfs; do
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
        ARCH="$ARCH" NEWLIB_INSTALL_ROOT="$ROOT_DIR/build/newlib-sysroot" ./tools/build_newlib.sh
    fi
fi

echo "=== Rebuilding userland ==="
make -C "$USERLAND_DIR" clean
make -C "$USERLAND_DIR" install \
    BUILD_NEWLIB="$BUILD_NEWLIB" \
    ENABLE_TCC="$BUILD_TCC" \
    ARCH="$ARCH" \
    NEWLIB_SYSROOT="$NEWLIB_SYSROOT"

if [ "$BUILD_TCC" = "1" ]; then
    echo "=== Building native TinyCC bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_tcc_native.sh
    rsync -a build/tcc-native/bundle/opt/tcc/ userfs/opt/tcc/
fi

if [ "$BUILD_BSD" = "1" ]; then
    echo "=== Building BSD tools bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bmake.sh
    rsync -a build/bmake/bundle/ userfs/
    cp build/bmake/bundle/opt/bmake/bin/bmake userfs/usr/bin/bmake
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdsed.sh
    rsync -a build/bsdsed/bundle/ userfs/
    ln -sfn ../opt/bsdsed/bin/sed userfs/bin/sed
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdawk.sh
    rsync -a build/bsdawk/bundle/ userfs/
    ln -sfn ../opt/bsdawk/bin/awk userfs/bin/awk
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdinstall.sh
    rsync -a build/bsdinstall/bundle/ userfs/
    ln -sfn ../../opt/bsdinstall/bin/install userfs/usr/bin/install
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdmtree.sh
    rsync -a build/bsdmtree/bundle/ userfs/
    mkdir -p userfs/usr/bin userfs/usr/sbin
    ln -sfn ../../opt/bsdmtree/bin/mtree userfs/usr/bin/mtree
    ln -sfn ../../opt/bsdmtree/bin/mtree userfs/usr/sbin/mtree
fi

echo "=== Rebuilding kernel ==="
make platform-kernel ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

echo "=== Recreating disk image ==="
rm -f disk.img fat32.img ext2.img "build/images/disk-${TARGET_PLATFORM}.img"
make platform-disk ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

echo "=== Booting QEMU ==="
echo "QEMU: $("$QEMU" --version | head -n 1)"
QEMU="$QEMU" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM" ./boot.sh

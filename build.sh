#!/usr/bin/env bash
# build.sh - rebuild ArmOS without launching QEMU.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_ARCH="${TARGET_ARCH:-arm64}"
TARGET_PLATFORM="${TARGET_PLATFORM:-raspi3}"
if [ "$TARGET_ARCH" = "arm64" ]; then
    ARCH="${ARCH:-aarch64-elf-}"
else
    ARCH="${ARCH:-arm-none-eabi-}"
fi
BUILD_XV_DEPS="${BUILD_XV_DEPS:-0}"
BUILD_ALL_USERLAND="${BUILD_ALL_USERLAND:-0}"
BUILD_NEWLIB="${BUILD_NEWLIB:-1}"
BUILD_BSD="${BUILD_BSD:-0}"
if [ "$BUILD_ALL_USERLAND" = "1" ]; then
    BUILD_TCC=1
    BUILD_BSD=1
    BUILD_NCURSES=1
    BUILD_NANO=1
    BUILD_ZLIB=1
    BUILD_LIBJPEG=1
    BUILD_LIBPNG=1
    BUILD_LIBTIFF=1
    BUILD_FBVIEW=1
    BUILD_XV_DEPS=1
fi
if [ "$BUILD_XV_DEPS" = "1" ]; then
    BUILD_TCC="${BUILD_TCC:-0}"
    BUILD_ZLIB="${BUILD_ZLIB:-1}"
    BUILD_LIBJPEG="${BUILD_LIBJPEG:-1}"
    BUILD_LIBPNG="${BUILD_LIBPNG:-1}"
    BUILD_LIBTIFF="${BUILD_LIBTIFF:-1}"
    BUILD_FBVIEW="${BUILD_FBVIEW:-1}"
else
    BUILD_TCC="${BUILD_TCC:-1}"
    BUILD_ZLIB="${BUILD_ZLIB:-0}"
    BUILD_LIBJPEG="${BUILD_LIBJPEG:-0}"
    BUILD_LIBPNG="${BUILD_LIBPNG:-0}"
    BUILD_LIBTIFF="${BUILD_LIBTIFF:-0}"
    BUILD_FBVIEW="${BUILD_FBVIEW:-0}"
fi
BUILD_NCURSES="${BUILD_NCURSES:-0}"
BUILD_NANO="${BUILD_NANO:-0}"

# shellcheck source=tools/cross_target_env.sh
source "$ROOT_DIR/tools/cross_target_env.sh"
IMAGE_SUFFIX="${TARGET_ARCH}-${TARGET_PLATFORM}"

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

if [ -d /opt/homebrew/opt/e2fsprogs/sbin ]; then
    export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
fi
if [ -d /usr/local/opt/e2fsprogs/sbin ]; then
    export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
fi

cd "$ROOT_DIR"

echo "=== BUILD ARMOS ==="
echo "Target: ${TARGET_ARCH}/${TARGET_PLATFORM}"

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
        TARGET="$TARGET_TRIPLET" ARCH="$ARCH" \
            NEWLIB_INSTALL_ROOT="$ROOT_DIR/build/newlib-sysroot" \
            ./tools/build_newlib.sh
    fi
fi

echo "=== Rebuilding userland ==="
make -C userland clean TARGET_ARCH="$TARGET_ARCH" ARCH="$ARCH"
make -C userland install \
    TARGET_ARCH="$TARGET_ARCH" \
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
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdxargs.sh
    rsync -a build/bsdxargs/bundle/ userfs/
    ln -sfn ../../opt/bsdxargs/bin/xargs userfs/usr/bin/xargs
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsddiff.sh
    rsync -a build/bsddiff/bundle/ userfs/
    ln -sfn ../../opt/bsddiff/bin/diff userfs/usr/bin/diff
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdpatch.sh
    rsync -a build/bsdpatch/bundle/ userfs/
    ln -sfn ../../opt/bsdpatch/bin/patch userfs/usr/bin/patch
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdpax.sh
    rsync -a build/bsdpax/bundle/ userfs/
    ln -sfn ../../opt/bsdpax/bin/pax userfs/usr/bin/pax
    ln -sfn ../../opt/bsdpax/bin/tar userfs/usr/bin/tar
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdm4.sh
    rsync -a build/bsdm4/bundle/ userfs/
    ln -sfn ../../opt/bsdm4/bin/m4 userfs/usr/bin/m4
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_bsdelftools.sh
    rsync -a build/bsdelftools/bundle/ userfs/
    for tool in ar ranlib nm strip size; do
        ln -sfn ../../opt/bsdelftools/bin/$tool userfs/usr/bin/$tool
    done
fi

if [ "$BUILD_ZLIB" = "1" ]; then
    echo "=== Building zlib bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_zlib.sh
    rsync -a build/zlib/bundle/ userfs/
fi

if [ "$BUILD_LIBJPEG" = "1" ]; then
    echo "=== Building libjpeg bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libjpeg.sh
    rsync -a build/libjpeg/bundle/ userfs/
fi

if [ "$BUILD_LIBPNG" = "1" ]; then
    if [ ! -f build/zlib/bundle/opt/zlib/lib/libz.a ]; then
        echo "=== Building zlib bundle for libpng ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_zlib.sh
    fi
    rsync -a build/zlib/bundle/ userfs/
    echo "=== Building libpng bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libpng.sh
    rsync -a build/libpng/bundle/ userfs/
fi

if [ "$BUILD_LIBTIFF" = "1" ]; then
    if [ ! -f build/zlib/bundle/opt/zlib/lib/libz.a ]; then
        echo "=== Building zlib bundle for libtiff ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_zlib.sh
    fi
    if [ ! -f build/libjpeg/bundle/opt/libjpeg/lib/libjpeg.a ]; then
        echo "=== Building libjpeg bundle for libtiff ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libjpeg.sh
    fi
    rsync -a build/zlib/bundle/ userfs/
    rsync -a build/libjpeg/bundle/ userfs/
    echo "=== Building libtiff bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libtiff.sh
    rsync -a build/libtiff/bundle/ userfs/
fi

if [ "$BUILD_FBVIEW" = "1" ]; then
    if [ ! -f build/zlib/bundle/opt/zlib/lib/libz.a ]; then
        echo "=== Building zlib bundle for fbview ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_zlib.sh
    fi
    if [ ! -f build/libjpeg/bundle/opt/libjpeg/lib/libjpeg.a ]; then
        echo "=== Building libjpeg bundle for fbview ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libjpeg.sh
    fi
    if [ ! -f build/libpng/bundle/opt/libpng/lib/libpng.a ]; then
        echo "=== Building libpng bundle for fbview ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libpng.sh
    fi
    if [ ! -f build/libtiff/bundle/opt/libtiff/lib/libtiff.a ]; then
        echo "=== Building libtiff bundle for fbview ==="
        ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_libtiff.sh
    fi
    rsync -a build/zlib/bundle/ userfs/
    rsync -a build/libjpeg/bundle/ userfs/
    rsync -a build/libpng/bundle/ userfs/
    rsync -a build/libtiff/bundle/ userfs/
    echo "=== Building fbview ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_fbview.sh
    rsync -a build/fbview/bundle/ userfs/
fi

if [ "$BUILD_NCURSES" = "1" ]; then
    echo "=== Building ncurses bundle ==="
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_ncurses.sh
    rsync -a build/ncurses/bundle/ userfs/
fi

if [ "$BUILD_NANO" = "1" ]; then
    echo "=== Building nano bundle ==="
    if [ "$BUILD_NCURSES" != "1" ] && [ ! -f userfs/opt/ncurses/lib/libncurses.a ]; then
        echo "Error: nano requires the ncurses bundle in userfs/opt/ncurses" >&2
        echo "Hint: rerun with BUILD_NCURSES=1 BUILD_NANO=1" >&2
        exit 1
    fi
    ARCH="$ARCH" NEWLIB_SYSROOT="$NEWLIB_SYSROOT" ./tools/build_nano.sh
    rsync -a build/nano/bundle/ userfs/
fi

echo "=== Rebuilding kernel ==="
make platform-kernel ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

echo "=== Recreating disk image ==="
rm -f disk.img fat32.img ext2.img "build/images/disk-${IMAGE_SUFFIX}.img"
make platform-disk ARCH="$ARCH" CROSS_COMPILE="$ARCH" TARGET_ARCH="$TARGET_ARCH" TARGET_PLATFORM="$TARGET_PLATFORM"

echo "=== Validating installed userfs ELF architecture ==="
TARGET_ARCH="$TARGET_ARCH" ARCH="$ARCH" ./tools/validate_userfs_arch.sh

echo "=== BUILD DONE ==="
echo "Kernel image: build/images/kernel-${IMAGE_SUFFIX}.bin"
echo "Disk image:   build/images/disk-${IMAGE_SUFFIX}.img"
echo "Boot existing build with: ./boot.sh"
echo "Rebuild and boot with:    ./run.sh"

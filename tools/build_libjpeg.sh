#!/usr/bin/env bash
# build_libjpeg.sh - cross-build a static libjpeg bundle for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/userland/opt/libjpeg/src}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/libjpeg}"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/libjpeg"
BUNDLE_USR_BIN="$BUNDLE_ROOT/usr/bin"

ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
AR="${ARCH}ar"
RANLIB="${ARCH}ranlib"
STRIP="${ARCH}strip"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
LIBGCC="${LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"
RUNTIME_OBJECTS="$ROOT_DIR/newlib-port/build/crt0_newlib.o $ROOT_DIR/newlib-port/build/syscall_raw.o $ROOT_DIR/newlib-port/build/syscalls.o"
JPGTEST_SRC="$ROOT_DIR/third_party/libjpeg/jpgtest.c"

LIBJPEG_SRCS=(
    jaricom.c
    jcapimin.c
    jcapistd.c
    jcarith.c
    jccoefct.c
    jccolor.c
    jcdctmgr.c
    jchuff.c
    jcinit.c
    jcmainct.c
    jcmarker.c
    jcmaster.c
    jcomapi.c
    jcparam.c
    jcprepct.c
    jcsample.c
    jctrans.c
    jdapimin.c
    jdapistd.c
    jdarith.c
    jdatadst.c
    jdatasrc.c
    jdcoefct.c
    jdcolor.c
    jddctmgr.c
    jdhuff.c
    jdinput.c
    jdmainct.c
    jdmarker.c
    jdmaster.c
    jdmerge.c
    jdpostct.c
    jdsample.c
    jdtrans.c
    jerror.c
    jfdctflt.c
    jfdctfst.c
    jfdctint.c
    jidctflt.c
    jidctfst.c
    jidctint.c
    jquant1.c
    jquant2.c
    jutils.c
    jmemmgr.c
    jmemnobs.c
)

if [ ! -f "$SRC_DIR/jpeglib.h" ] || [ ! -f "$SRC_DIR/jconfig.h" ]; then
    echo "error: libjpeg source not found in $SRC_DIR" >&2
    exit 1
fi

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_LIBC" ]; then
    echo "error: newlib sysroot is incomplete: $NEWLIB_SYSROOT" >&2
    echo "hint: run ./tools/build_newlib.sh first" >&2
    exit 1
fi

if [ ! -f "$ROOT_DIR/newlib-port/build/crt0_newlib.o" ] ||
   [ ! -f "$ROOT_DIR/newlib-port/build/syscall_raw.o" ] ||
   [ ! -f "$ROOT_DIR/newlib-port/build/syscalls.o" ]; then
    echo "error: newlib-port runtime objects are missing" >&2
    echo "hint: make -C newlib-port NEWLIB_SYSROOT=$NEWLIB_SYSROOT" >&2
    exit 1
fi

rm -rf "$BUILD_DIR" "$BUNDLE_ROOT"
mkdir -p "$BUILD_DIR" "$BUNDLE_PREFIX/include" "$BUNDLE_PREFIX/lib" "$BUNDLE_USR_BIN"

CFLAGS="$ARM_FLAGS -std=gnu99 -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -I$SRC_DIR -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include"
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition"

OBJECTS=()
for src in "${LIBJPEG_SRCS[@]}"; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$SRC_DIR/$src" -o "$obj"
    OBJECTS+=("$obj")
done

"$AR" rcs "$BUNDLE_PREFIX/lib/libjpeg.a" "${OBJECTS[@]}"
"$RANLIB" "$BUNDLE_PREFIX/lib/libjpeg.a"

cp "$SRC_DIR/jconfig.h" "$SRC_DIR/jerror.h" "$SRC_DIR/jmorecfg.h" "$SRC_DIR/jpeglib.h" "$BUNDLE_PREFIX/include/"

"$CC" $CFLAGS -c "$JPGTEST_SRC" -o "$BUILD_DIR/jpgtest.o"
"$CC" $LDFLAGS -o "$BUNDLE_USR_BIN/jpgtest" \
    $RUNTIME_OBJECTS \
    "$BUILD_DIR/jpgtest.o" \
    "$BUNDLE_PREFIX/lib/libjpeg.a" \
    "$NEWLIB_LIBC" \
    "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_USR_BIN/jpgtest" || true

echo
echo "ArmOS libjpeg bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"

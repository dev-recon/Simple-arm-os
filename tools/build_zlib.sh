#!/usr/bin/env bash
# build_zlib.sh - cross-build a static zlib bundle for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/userland/opt/zlib/src}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/zlib}"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/zlib"
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
ZTEST_SRC="$ROOT_DIR/third_party/zlib/ztest.c"

ZLIB_SRCS=(
    adler32.c
    compress.c
    crc32.c
    deflate.c
    gzclose.c
    gzlib.c
    gzread.c
    gzwrite.c
    infback.c
    inffast.c
    inflate.c
    inftrees.c
    trees.c
    uncompr.c
    zutil.c
)

if [ ! -f "$SRC_DIR/zlib.h" ] || [ ! -f "$SRC_DIR/zconf.h" ]; then
    echo "error: zlib source not found in $SRC_DIR" >&2
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

CFLAGS="$ARM_FLAGS -std=gnu99 -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -I$SRC_DIR -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include"
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition"

OBJECTS=()
for src in "${ZLIB_SRCS[@]}"; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$SRC_DIR/$src" -o "$obj"
    OBJECTS+=("$obj")
done

"$AR" rcs "$BUNDLE_PREFIX/lib/libz.a" "${OBJECTS[@]}"
"$RANLIB" "$BUNDLE_PREFIX/lib/libz.a"

cp "$SRC_DIR/zlib.h" "$SRC_DIR/zconf.h" "$BUNDLE_PREFIX/include/"

"$CC" $CFLAGS -c "$ZTEST_SRC" -o "$BUILD_DIR/ztest.o"
"$CC" $LDFLAGS -o "$BUNDLE_USR_BIN/ztest" \
    $RUNTIME_OBJECTS \
    "$BUILD_DIR/ztest.o" \
    "$BUNDLE_PREFIX/lib/libz.a" \
    "$NEWLIB_LIBC" \
    "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_USR_BIN/ztest" || true

echo
echo "ArmOS zlib bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"

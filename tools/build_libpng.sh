#!/usr/bin/env bash
# build_libpng.sh - cross-build a static libpng bundle for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/userland/opt/libpng/src}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/libpng}"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/libpng"
BUNDLE_USR_BIN="$BUNDLE_ROOT/usr/bin"
ZLIB_PREFIX="${ZLIB_PREFIX:-$ROOT_DIR/build/zlib/bundle/opt/zlib}"

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
PNGTEST_SRC="$ROOT_DIR/third_party/libpng/pngtest.c"

LIBPNG_SRCS=(
    png.c
    pngerror.c
    pngget.c
    pngmem.c
    pngpread.c
    pngread.c
    pngrio.c
    pngrtran.c
    pngrutil.c
    pngset.c
    pngtrans.c
    pngwio.c
    pngwrite.c
    pngwtran.c
    pngwutil.c
)

if [ ! -f "$SRC_DIR/png.h" ] || [ ! -f "$SRC_DIR/pnglibconf.h" ]; then
    echo "error: libpng source not found in $SRC_DIR" >&2
    exit 1
fi

if [ ! -f "$ZLIB_PREFIX/include/zlib.h" ] || [ ! -f "$ZLIB_PREFIX/lib/libz.a" ]; then
    echo "error: zlib bundle not found: $ZLIB_PREFIX" >&2
    echo "hint: run ./tools/build_zlib.sh first" >&2
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

CFLAGS="$ARM_FLAGS -std=gnu99 -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -DPNG_ARM_NEON_OPT=0 -I$SRC_DIR -I$ZLIB_PREFIX/include -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include"
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition"

OBJECTS=()
for src in "${LIBPNG_SRCS[@]}"; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$SRC_DIR/$src" -o "$obj"
    OBJECTS+=("$obj")
done

"$AR" rcs "$BUNDLE_PREFIX/lib/libpng.a" "${OBJECTS[@]}"
"$RANLIB" "$BUNDLE_PREFIX/lib/libpng.a"

cp "$SRC_DIR/png.h" "$SRC_DIR/pngconf.h" "$SRC_DIR/pnglibconf.h" "$BUNDLE_PREFIX/include/"

"$CC" $CFLAGS -c "$PNGTEST_SRC" -o "$BUILD_DIR/pngtest.o"
"$CC" $LDFLAGS -o "$BUNDLE_USR_BIN/pngtest" \
    $RUNTIME_OBJECTS \
    "$BUILD_DIR/pngtest.o" \
    "$BUNDLE_PREFIX/lib/libpng.a" \
    "$ZLIB_PREFIX/lib/libz.a" \
    "$NEWLIB_LIBC" \
    "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_USR_BIN/pngtest" || true

echo
echo "ArmOS libpng bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"

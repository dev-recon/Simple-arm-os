#!/usr/bin/env bash
# build_bsdawk.sh - cross-build NetBSD nawk for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/userland/opt/bsdawk/src}"
COMPAT_DIR="${COMPAT_DIR:-$ROOT_DIR/userland/opt/bsdawk/compat}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/bsdawk}"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/bsdawk"
BUNDLE_BIN="$BUNDLE_PREFIX/bin"

ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
STRIP="${ARCH}strip"
BISON="${BISON:-bison}"
HOSTCC="${HOSTCC:-cc}"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
NEWLIB_LIBM="${NEWLIB_LIBM:-$NEWLIB_SYSROOT/lib/libm.a}"
LIBGCC="${LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"

if [ ! -f "$SRC_DIR/awkgram.y" ] || [ ! -f "$SRC_DIR/main.c" ]; then
    echo "error: NetBSD nawk sources not found in $SRC_DIR" >&2
    exit 1
fi

if ! command -v "$BISON" >/dev/null 2>&1; then
    echo "error: required parser generator '$BISON' not found in PATH" >&2
    exit 1
fi

if ! command -v "$HOSTCC" >/dev/null 2>&1; then
    echo "error: required host compiler '$HOSTCC' not found in PATH" >&2
    exit 1
fi

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] ||
   [ ! -f "$NEWLIB_LIBC" ] ||
   [ ! -f "$NEWLIB_LIBM" ]; then
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
mkdir -p "$BUILD_DIR" "$BUNDLE_BIN"

"$BISON" -d -o "$BUILD_DIR/awkgram.c" "$SRC_DIR/awkgram.y"

HOST_CFLAGS="-std=gnu11 -I$COMPAT_DIR -I$BUILD_DIR -I$SRC_DIR -include $COMPAT_DIR/armos_compat.h"
"$HOSTCC" $HOST_CFLAGS "$SRC_DIR/maketab.c" -o "$BUILD_DIR/maketab"
"$BUILD_DIR/maketab" "$BUILD_DIR/awkgram.h" > "$BUILD_DIR/proctab.c"

CFLAGS="$ARM_FLAGS -std=gnu11 -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -I$COMPAT_DIR -I$BUILD_DIR -I$SRC_DIR -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include -include $COMPAT_DIR/armos_compat.h"
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition"
RUNTIME_OBJECTS="$ROOT_DIR/newlib-port/build/crt0_newlib.o $ROOT_DIR/newlib-port/build/syscall_raw.o $ROOT_DIR/newlib-port/build/syscalls.o"

objects=()
for src in awkgram.c proctab.c; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$BUILD_DIR/$src" -o "$obj"
    objects+=("$obj")
done

for src in b.c lex.c lib.c main.c parse.c run.c tran.c; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$SRC_DIR/$src" -o "$obj"
    objects+=("$obj")
done

"$CC" $CFLAGS -c "$COMPAT_DIR/compat.c" -o "$BUILD_DIR/compat.o"
objects+=("$BUILD_DIR/compat.o")

"$CC" $LDFLAGS -o "$BUNDLE_BIN/awk" \
    $RUNTIME_OBJECTS \
    "${objects[@]}" \
    "$NEWLIB_LIBM" "$NEWLIB_LIBC" "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_BIN/awk" || true

echo
echo "ArmOS BSD awk bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"
echo "  ln -sfn ../opt/bsdawk/bin/awk $ROOT_DIR/userfs/bin/awk"

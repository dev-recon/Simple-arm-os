#!/usr/bin/env bash
# build_bsdm4.sh - cross-build NetBSD m4 for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT_DIR/userland/opt/bsdm4/src}"
COMPAT_DIR="${COMPAT_DIR:-$ROOT_DIR/userland/opt/bsdm4/compat}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/bsdm4}"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/bsdm4"
BUNDLE_BIN="$BUNDLE_PREFIX/bin"

ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
STRIP="${ARCH}strip"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
NEWLIB_LIBM="${NEWLIB_LIBM:-$NEWLIB_SYSROOT/lib/libm.a}"
LIBGCC="${LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"

if [ ! -f "$SRC_DIR/main.c" ] || [ ! -f "$SRC_DIR/parser.y" ] || [ ! -f "$SRC_DIR/tokenizer.l" ]; then
    echo "error: NetBSD m4 sources not found in $SRC_DIR" >&2
    exit 1
fi

if ! command -v yacc >/dev/null 2>&1; then
    echo "error: yacc is required to generate the m4 expression parser" >&2
    exit 1
fi

if ! command -v flex >/dev/null 2>&1; then
    echo "error: flex is required to generate the m4 expression tokenizer" >&2
    exit 1
fi

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_LIBC" ] || [ ! -f "$NEWLIB_LIBM" ]; then
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

for regex_symbol in regcomp regexec regerror regfree; do
    if ! "$ARCH"nm -g "$NEWLIB_LIBC" | grep -E " T ${regex_symbol}$" >/dev/null; then
        echo "error: newlib libc.a does not provide POSIX regex symbol: $regex_symbol" >&2
        echo "hint: run ./tools/build_newlib.sh after applying the ArmOS newlib patches" >&2
        exit 1
    fi
done

rm -rf "$BUILD_DIR" "$BUNDLE_ROOT"
mkdir -p "$BUILD_DIR" "$BUNDLE_BIN"

yacc -d -o "$BUILD_DIR/parser.c" "$SRC_DIR/parser.y"
flex -o "$BUILD_DIR/tokenizer.c" "$SRC_DIR/tokenizer.l"

CFLAGS="$ARM_FLAGS -std=gnu99 -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -DEXTENDED -DYYSTYPE=int32_t -I$BUILD_DIR -I$COMPAT_DIR -I$SRC_DIR/lib -I$SRC_DIR -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include -include $COMPAT_DIR/armos_compat.h"
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition"
RUNTIME_OBJECTS="$ROOT_DIR/newlib-port/build/crt0_newlib.o $ROOT_DIR/newlib-port/build/syscall_raw.o $ROOT_DIR/newlib-port/build/syscalls.o"

objects=()
for src in parser.c tokenizer.c; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$BUILD_DIR/$src" -o "$obj"
    objects+=("$obj")
done

for src in eval.c expr.c look.c main.c misc.c gnum4.c trace.c; do
    obj="$BUILD_DIR/${src%.c}.o"
    "$CC" $CFLAGS -c "$SRC_DIR/$src" -o "$obj"
    objects+=("$obj")
done

"$CC" $CFLAGS -c "$SRC_DIR/lib/ohash.c" -o "$BUILD_DIR/ohash.o"
objects+=("$BUILD_DIR/ohash.o")

"$CC" $CFLAGS -c "$COMPAT_DIR/compat.c" -o "$BUILD_DIR/compat.o"
objects+=("$BUILD_DIR/compat.o")

"$CC" $LDFLAGS -o "$BUNDLE_BIN/m4" \
    $RUNTIME_OBJECTS \
    "${objects[@]}" \
    "$NEWLIB_LIBM" "$NEWLIB_LIBC" "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_BIN/m4" || true

echo
echo "ArmOS BSD m4 bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"
echo "  ln -sfn ../../opt/bsdm4/bin/m4 $ROOT_DIR/userfs/usr/bin/m4"

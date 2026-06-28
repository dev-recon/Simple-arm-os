#!/usr/bin/env bash
# build_tcc_native.sh - build a native ArmOS TinyCC bundle.
#
# This helper intentionally builds out of the vendored upstream tree.  The
# native compiler is a normal ArmOS/newlib executable, while the programs it
# later produces use the smaller newlib-port/tcc runtime glue to avoid pulling
# duplicate high-level POSIX wrappers into TinyCC's linker.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT_DIR/userland/opt/tcc/src"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/tcc-native}"
PATCHED_SRC="$WORK_DIR/src"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_DIR="$WORK_DIR/bundle/opt/tcc"
ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
AR="${ARCH}ar"
HOST_CC="${HOST_CC:-clang}"

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
NEWLIB_LIBM="${NEWLIB_LIBM:-$NEWLIB_SYSROOT/lib/libm.a}"

# TinyCC crashes when linking ArmOS/newlib binaries with GCC's Thumb multilib
# libgcc.  The root ARM/EABI archive is the compatible runtime for this port.
TCC_LIBGCC="${TCC_LIBGCC:-$("$CC" -print-libgcc-file-name)}"
NATIVE_LIBGCC="${NATIVE_LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"

if [ ! -f "$SRC_DIR/configure" ]; then
    echo "error: TinyCC sources not found in $SRC_DIR" >&2
    exit 1
fi

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_LIBC" ]; then
    echo "error: newlib sysroot is incomplete: $NEWLIB_SYSROOT" >&2
    echo "hint: run ./tools/build_newlib.sh and ./build.sh first" >&2
    exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$PATCHED_SRC" "$BUILD_DIR/armos-include/sys" "$BUNDLE_DIR/bin" \
         "$BUNDLE_DIR/lib/tcc/include" "$BUNDLE_DIR/include"

cp -R "$SRC_DIR"/. "$PATCHED_SRC"/

# ArmOS/newlib typedefs uint32_t as unsigned long on this target.  Upstream TCC
# declares o() as unsigned int in tcc.h, so keep the ARM backend signature
# exactly aligned with the public prototype.
perl -0pi -e 's/void o\(uint32_t i\)/void o(unsigned int i)/' "$PATCHED_SRC/arm-gen.c"

# The first native milestone does not support tcc -run.  A small mman header is
# still needed because tccrun.c is part of libtcc even when runtime execution is
# effectively disabled by the ArmOS build profile.
cat > "$BUILD_DIR/armos-include/sys/mman.h" <<'EOF'
#ifndef ARMOS_PORT_SYS_MMAN_H
#define ARMOS_PORT_SYS_MMAN_H

#include <stddef.h>

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_FAILED    ((void *)-1)

void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
int munmap(void *addr, size_t length);
int mprotect(void *addr, size_t length, int prot);

#endif
EOF

cd "$BUILD_DIR"

"$PATCHED_SRC/configure" \
    --source-path="$PATCHED_SRC" \
    --prefix=/opt/tcc \
    --cc="$CC $ARM_FLAGS -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -I$NEWLIB_SYSROOT/include" \
    --ar="$AR" \
    --cpu=arm \
    --targetos=Linux \
    --enable-static \
    --disable-rpath \
    --sysincludepaths=/opt/tcc/lib/tcc/include:/opt/tcc/include \
    --libpaths=/opt/tcc/lib \
    --crtprefix=/opt/tcc/lib

# TCC's c2str generator is a build-host utility.  Keep it as a macOS binary
# even though the compiler being produced is an ArmOS ARM executable.
"$HOST_CC" -DC2STR "$PATCHED_SRC/conftest.c" -o "$BUILD_DIR/c2str.exe"

TCC_CFLAGS="-Wall -O2 -Wdeclaration-after-statement -Wno-unused-result"
TCC_CFLAGS="$TCC_CFLAGS -DCONFIG_TCC_STATIC -DCONFIG_TCC_SEMLOCK=0 -DCONFIG_TCC_BACKTRACE=0"
TCC_CFLAGS="$TCC_CFLAGS -I$BUILD_DIR/armos-include"

NATIVE_LDFLAGS="-nostdlib -nostartfiles -static"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS -Wl,--allow-multiple-definition"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS $ROOT_DIR/newlib-port/build/crt0_newlib.o"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS $ROOT_DIR/newlib-port/build/syscall_raw.o"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS $ROOT_DIR/newlib-port/build/syscalls.o"
NATIVE_LDFLAGS="$NATIVE_LDFLAGS $NEWLIB_LIBM $NEWLIB_LIBC $NATIVE_LIBGCC"

make arm-eabi-tcc LIBS='' CFLAGS="$TCC_CFLAGS" LDFLAGS="$NATIVE_LDFLAGS"

"$CC" $ARM_FLAGS -std=gnu99 -ffreestanding -nostdlib -fno-builtin \
    -fno-stack-protector -ffunction-sections -fdata-sections -Os \
    -I"$ROOT_DIR/userland/include" \
    -I"$NEWLIB_SYSROOT/include" \
    -c "$ROOT_DIR/newlib-port/tcc/syscalls_min.c" \
    -o "$BUNDLE_DIR/lib/syscalls_min.o"

cp "$BUILD_DIR/arm-eabi-tcc" "$BUNDLE_DIR/bin/tcc"
cp "$ROOT_DIR/newlib-port/build/crt0_newlib.o" "$BUNDLE_DIR/lib/crt0_newlib.o"
cp "$ROOT_DIR/newlib-port/build/syscall_raw.o" "$BUNDLE_DIR/lib/syscall_raw.o"
cp "$NEWLIB_LIBC" "$BUNDLE_DIR/lib/libc.a"
cp "$NEWLIB_LIBM" "$BUNDLE_DIR/lib/libm.a"
cp "$TCC_LIBGCC" "$BUNDLE_DIR/lib/libgcc.a"
if [ -f "$BUILD_DIR/libtcc.a" ]; then
    cp "$BUILD_DIR/libtcc.a" "$BUNDLE_DIR/lib/libtcc.a"
fi
cp -R "$NEWLIB_SYSROOT/include"/. "$BUNDLE_DIR/include"/
# ArmOS owns a few public ABI headers that complement or override newlib's
# generic ones, notably termios.h and sys/ioctl.h for TTY-aware programs.
cp -R "$ROOT_DIR/userland/include"/. "$BUNDLE_DIR/include"/
cp -R "$PATCHED_SRC/include"/. "$BUNDLE_DIR/lib/tcc/include"/

echo
echo "Native ArmOS TinyCC bundle built:"
echo "  $BUNDLE_DIR"
echo
file "$BUNDLE_DIR/bin/tcc"
"${ARCH}objdump" -f "$BUNDLE_DIR/bin/tcc"
echo
echo "To stage it into the generated filesystem for testing:"
echo "  rsync -a $BUNDLE_DIR/ $ROOT_DIR/userfs/opt/tcc/"
echo
echo "Keep /opt/tcc/bin out of PATH: /usr/bin/tcc is the ArmOS wrapper that"
echo "adds the startup objects and libraries needed for normal native builds."

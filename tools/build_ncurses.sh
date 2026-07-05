#!/usr/bin/env bash
# build_ncurses.sh - cross-build a minimal static ncurses bundle for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
AR="${ARCH}ar"
RANLIB="${ARCH}ranlib"
STRIP="${ARCH}strip"
HOST_CC="${HOST_CC:-cc}"
NCURSES_VERSION="${NCURSES_VERSION:-6.5}"
NCURSES_URL="${NCURSES_URL:-https://ftp.gnu.org/pub/gnu/ncurses/ncurses-$NCURSES_VERSION.tar.gz}"

WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/ncurses}"
DOWNLOAD_DIR="$WORK_DIR/download"
SRC_ARCHIVE="$DOWNLOAD_DIR/ncurses-$NCURSES_VERSION.tar.gz"
SRC_DIR="$WORK_DIR/src"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/ncurses"
BUNDLE_USR_BIN="$BUNDLE_ROOT/usr/bin"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
LIBGCC="${LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"
TERMINFO_SRC="$ROOT_DIR/third_party/ncurses/armos.ti"
CURSESTEST_SRC="$ROOT_DIR/third_party/ncurses/cursestest.c"

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_LIBC" ]; then
    echo "error: newlib sysroot is incomplete: $NEWLIB_SYSROOT" >&2
    echo "hint: run ./tools/build_newlib.sh first" >&2
    exit 1
fi

if [ ! -f "$TERMINFO_SRC" ]; then
    echo "error: missing $TERMINFO_SRC" >&2
    exit 1
fi

mkdir -p "$DOWNLOAD_DIR"
if [ ! -f "$SRC_ARCHIVE" ]; then
    echo "=== Downloading ncurses $NCURSES_VERSION ==="
    curl -L --fail "$NCURSES_URL" -o "$SRC_ARCHIVE"
fi

rm -rf "$SRC_DIR" "$BUILD_DIR" "$BUNDLE_ROOT"
mkdir -p "$SRC_DIR" "$BUILD_DIR" "$BUNDLE_PREFIX" "$BUNDLE_USR_BIN"

tar -xzf "$SRC_ARCHIVE" -C "$SRC_DIR" --strip-components=1

# Make the ArmOS entry visible to ncurses' fallback generator.
cat "$TERMINFO_SRC" >> "$SRC_DIR/misc/terminfo.src"

cd "$BUILD_DIR"

BUILD_TRIPLET="$("$SRC_DIR/config.guess" 2>/dev/null || echo unknown)"

CC="$CC" \
AR="$AR" \
RANLIB="$RANLIB" \
BUILD_CC="$HOST_CC" \
CFLAGS="$ARM_FLAGS -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include" \
CPPFLAGS="-I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include" \
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition $ROOT_DIR/newlib-port/build/crt0_newlib.o $ROOT_DIR/newlib-port/build/syscall_raw.o $ROOT_DIR/newlib-port/build/syscalls.o" \
LIBS="$NEWLIB_LIBC $LIBGCC" \
"$SRC_DIR/configure" \
    --build="$BUILD_TRIPLET" \
    --host=arm-none-eabi \
    --target=arm-none-eabi \
    --prefix=/opt/ncurses \
    --with-build-cc="$HOST_CC" \
    --with-normal \
    --without-shared \
    --without-debug \
    --without-profile \
    --without-cxx \
    --without-cxx-binding \
    --without-ada \
    --without-manpages \
    --without-tests \
    --without-progs \
    --disable-widec \
    --disable-database \
    --disable-db-install \
    --with-fallbacks=armos,ansi \
    --without-hashed-db \
    --without-gpm \
    --without-dlsym

make -j"${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}" libs
make DESTDIR="$BUNDLE_ROOT" install.libs install.includes

for header in curses.h term.h termcap.h unctrl.h panel.h menu.h form.h eti.h; do
    if [ -f "$BUNDLE_PREFIX/include/ncurses/$header" ]; then
        ln -sf "ncurses/$header" "$BUNDLE_PREFIX/include/$header"
    fi
done

mkdir -p "$BUNDLE_PREFIX/share/terminfo"
cp "$TERMINFO_SRC" "$BUNDLE_PREFIX/share/terminfo/armos.ti"

"$CC" $ARM_FLAGS -std=gnu99 -Os -ffreestanding -fno-builtin \
    -fno-stack-protector -DARM_OS_NEWLIB \
    -I"$ROOT_DIR/userland/include" \
    -I"$NEWLIB_SYSROOT/include" \
    -I"$BUNDLE_PREFIX/include" \
    -I"$BUNDLE_PREFIX/include/ncurses" \
    -c "$CURSESTEST_SRC" \
    -o "$WORK_DIR/cursestest.o"

"$CC" $ARM_FLAGS -nostdlib -nostartfiles -static \
    -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections \
    -Wl,--allow-multiple-definition \
    -o "$BUNDLE_USR_BIN/cursestest" \
    "$ROOT_DIR/newlib-port/build/crt0_newlib.o" \
    "$ROOT_DIR/newlib-port/build/syscall_raw.o" \
    "$ROOT_DIR/newlib-port/build/syscalls.o" \
    "$WORK_DIR/cursestest.o" \
    "$BUNDLE_PREFIX/lib/libncurses.a" \
    "$NEWLIB_LIBC" \
    "$LIBGCC"

"$STRIP" --strip-all "$BUNDLE_USR_BIN/cursestest" || true

echo
echo "ArmOS ncurses bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"

#!/usr/bin/env bash
# build_nano.sh - cross-build a minimal static nano bundle for ArmOS.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"
CC="${ARCH}gcc"
STRIP="${ARCH}strip"
HOST_CC="${HOST_CC:-cc}"
NANO_VERSION="${NANO_VERSION:-8.7}"
NANO_URL="${NANO_URL:-https://www.nano-editor.org/dist/v8/nano-$NANO_VERSION.tar.xz}"

WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/nano}"
DOWNLOAD_DIR="$WORK_DIR/download"
SRC_ARCHIVE="$DOWNLOAD_DIR/nano-$NANO_VERSION.tar.xz"
SRC_DIR="$WORK_DIR/src"
BUILD_DIR="$WORK_DIR/build"
BUNDLE_ROOT="$WORK_DIR/bundle"
BUNDLE_PREFIX="$BUNDLE_ROOT/opt/nano"
BUNDLE_BIN="$BUNDLE_PREFIX/bin"

ARM_FLAGS="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft"
NEWLIB_SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/arm-none-eabi}"
NEWLIB_LIBC="${NEWLIB_LIBC:-$NEWLIB_SYSROOT/lib/libc.a}"
LIBGCC="${LIBGCC:-$("$CC" $ARM_FLAGS -print-libgcc-file-name)}"
NCURSES_PREFIX="${NCURSES_PREFIX:-$ROOT_DIR/userfs/opt/ncurses}"

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if [ ! -f "$NEWLIB_SYSROOT/include/stdio.h" ] || [ ! -f "$NEWLIB_LIBC" ]; then
    echo "error: newlib sysroot is incomplete: $NEWLIB_SYSROOT" >&2
    echo "hint: run ./tools/build_newlib.sh first" >&2
    exit 1
fi

if [ ! -f "$NCURSES_PREFIX/include/curses.h" ] || [ ! -f "$NCURSES_PREFIX/lib/libncurses.a" ]; then
    echo "error: missing ArmOS ncurses bundle: $NCURSES_PREFIX" >&2
    echo "hint: run ./tools/build_ncurses.sh and stage build/ncurses/bundle first" >&2
    exit 1
fi

mkdir -p "$DOWNLOAD_DIR"
if [ ! -f "$SRC_ARCHIVE" ]; then
    echo "=== Downloading nano $NANO_VERSION ==="
    curl -L --fail "$NANO_URL" -o "$SRC_ARCHIVE"
fi

rm -rf "$SRC_DIR" "$BUILD_DIR" "$BUNDLE_ROOT"
mkdir -p "$SRC_DIR" "$BUILD_DIR" "$BUNDLE_BIN"

tar -xJf "$SRC_ARCHIVE" -C "$SRC_DIR" --strip-components=1

cd "$BUILD_DIR"

# Keep the first port intentionally small.  nano's configure script comes from
# gnulib and normally probes a large Unix surface by executing test programs;
# for ArmOS cross-builds we pin the answers that matter for the tiny profile.
cat > config.cache <<'CACHE'
ac_cv_func_chown=yes
ac_cv_func_fchmod=yes
ac_cv_func_fsync=yes
ac_cv_func_getcwd=yes
ac_cv_func_getdtablesize=yes
ac_cv_func_getopt_long=yes
ac_cv_func_getprogname=yes
ac_cv_func_getrlimit=yes
ac_cv_func_getuid=yes
ac_cv_func_lstat=yes
ac_cv_func_memmove=yes
ac_cv_func_memset=yes
ac_cv_func_poll=yes
ac_cv_func_select=yes
ac_cv_func_setlocale=no
ac_cv_func_snprintf=yes
ac_cv_func_stat=yes
ac_cv_func_strcasecmp=yes
ac_cv_func_strncasecmp=yes
ac_cv_func_strstr=yes
ac_cv_func_tcgetattr=yes
ac_cv_func_tcsetattr=yes
ac_cv_func_unlink=yes
ac_cv_func_vsnprintf=yes
ac_cv_header_glob_h=no
ac_cv_header_regex_h=yes
ac_cv_header_sys_resource_h=yes
ac_cv_header_sys_ioctl_h=yes
ac_cv_header_sys_select_h=yes
ac_cv_header_termios_h=yes
ac_cv_header_wchar_h=yes
ac_cv_lib_ncurses_initscr=yes
gl_cv_func_getcwd_path_max=yes
gl_cv_func_malloc_posix=yes
gl_cv_func_realloc_posix=yes
gl_cv_func_snprintf_posix=yes
gl_cv_func_vsnprintf_posix=yes
gl_cv_glob_overflows_stack=no
gl_cv_have_include_next=yes
gt_cv_func_gettext_libc=no
gt_cv_func_gettext_libintl=no
am_cv_func_iconv=no
CACHE

BUILD_TRIPLET="$("$SRC_DIR/config.guess" 2>/dev/null || echo unknown)"

CC="$CC" \
BUILD_CC="$HOST_CC" \
CFLAGS="$ARM_FLAGS -Os -ffreestanding -fno-builtin -fno-stack-protector -DARM_OS_NEWLIB -I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include -I$NCURSES_PREFIX/include -I$NCURSES_PREFIX/include/ncurses" \
CPPFLAGS="-I$ROOT_DIR/userland/include -I$NEWLIB_SYSROOT/include -I$NCURSES_PREFIX/include -I$NCURSES_PREFIX/include/ncurses" \
NCURSES_CFLAGS="-I$NCURSES_PREFIX/include -I$NCURSES_PREFIX/include/ncurses" \
NCURSES_LIBS="$NCURSES_PREFIX/lib/libncurses.a" \
LDFLAGS="$ARM_FLAGS -nostdlib -nostartfiles -static -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections -Wl,--allow-multiple-definition $ROOT_DIR/newlib-port/build/crt0_newlib.o $ROOT_DIR/newlib-port/build/syscall_raw.o $ROOT_DIR/newlib-port/build/syscalls.o" \
LIBS="$NCURSES_PREFIX/lib/libncurses.a $NEWLIB_LIBC $LIBGCC" \
"$SRC_DIR/configure" \
    --cache-file="$BUILD_DIR/config.cache" \
    --build="$BUILD_TRIPLET" \
    --host=arm-none-eabi \
    --prefix=/opt/nano \
    --enable-tiny \
    --disable-nls \
    --disable-utf8 \
    --disable-browser \
    --disable-color \
    --disable-extra \
    --disable-help \
    --disable-histories \
    --disable-justify \
    --disable-libmagic \
    --disable-multibuffer \
    --disable-operatingdir \
    --disable-speller \
    --disable-tabcomp \
    --disable-wordcomp \
    --disable-wrapping

make -j"${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
make DESTDIR="$BUNDLE_ROOT" install-exec

"$STRIP" --strip-all "$BUNDLE_BIN/nano" || true

echo
echo "ArmOS nano bundle built:"
echo "  $BUNDLE_ROOT"
echo
echo "Stage with:"
echo "  rsync -a $BUNDLE_ROOT/ $ROOT_DIR/userfs/"

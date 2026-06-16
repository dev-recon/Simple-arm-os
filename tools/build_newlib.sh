#!/usr/bin/env bash
# Build a repo-local newlib sysroot for arm-os userland experiments.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-arm-none-eabi-}"
TARGET="${TARGET:-arm-none-eabi}"
NEWLIB_VERSION="${NEWLIB_VERSION:-4.4.0.20231231}"
ARCHIVE="${NEWLIB_ARCHIVE:-$ROOT_DIR/newlib-$NEWLIB_VERSION.tar.gz}"
NEWLIB_URL="${NEWLIB_URL:-https://sourceware.org/pub/newlib/newlib-$NEWLIB_VERSION.tar.gz}"
BUILD_ROOT="${NEWLIB_BUILD_ROOT:-$ROOT_DIR/build/newlib-build}"
INSTALL_ROOT="${NEWLIB_INSTALL_ROOT:-$ROOT_DIR/build/newlib-sysroot}"
SYSROOT="$INSTALL_ROOT/$TARGET"
SRC_DIR="$BUILD_ROOT/src/newlib-$NEWLIB_VERSION"
OBJ_DIR="$BUILD_ROOT/obj"
PATCH_DIR="${NEWLIB_PATCH_DIR:-$ROOT_DIR/patches/newlib-$NEWLIB_VERSION}"
PATCH_SERIES="$PATCH_DIR/series"
PATCH_STAMP="$SRC_DIR/.arm-os-patches-applied"

export PATH="/opt/homebrew/Cellar/arm-none-eabi-gcc/15.1.0/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:$PATH"

if ! command -v "${ARCH}gcc" >/dev/null 2>&1; then
    echo "Error: ${ARCH}gcc not found in PATH" >&2
    exit 1
fi

if [ ! -f "$ARCHIVE" ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "Error: newlib archive not found and curl is unavailable: $ARCHIVE" >&2
        echo "Place newlib-$NEWLIB_VERSION.tar.gz at the repository root, set NEWLIB_ARCHIVE, or install curl." >&2
        exit 1
    fi

    echo "=== Downloading newlib $NEWLIB_VERSION ==="
    echo "Source: $NEWLIB_URL"
    curl -L "$NEWLIB_URL" -o "$ARCHIVE"
fi

mkdir -p "$BUILD_ROOT/src" "$OBJ_DIR" "$INSTALL_ROOT"

if [ ! -d "$SRC_DIR" ]; then
    echo "=== Extracting newlib $NEWLIB_VERSION ==="
    tar -xzf "$ARCHIVE" -C "$BUILD_ROOT/src"
fi

if [ -f "$PATCH_SERIES" ]; then
    if [ ! -f "$PATCH_STAMP" ]; then
        echo "=== Applying arm-os newlib patches ==="
        while IFS= read -r patch_name || [ -n "$patch_name" ]; do
            case "$patch_name" in
                ""|\#*) continue ;;
            esac

            patch_file="$PATCH_DIR/$patch_name"
            if [ ! -f "$patch_file" ]; then
                echo "Error: listed newlib patch not found: $patch_file" >&2
                exit 1
            fi

            echo "Applying $patch_name"
            patch -d "$SRC_DIR" -p1 < "$patch_file"
        done < "$PATCH_SERIES"
        date -u +"%Y-%m-%dT%H:%M:%SZ" > "$PATCH_STAMP"
    else
        echo "=== arm-os newlib patches already applied ==="
    fi
fi

echo "=== Configuring newlib for $TARGET ==="
(
    cd "$OBJ_DIR"
    "$SRC_DIR/configure" \
        --target="$TARGET" \
        --prefix="$INSTALL_ROOT" \
        --disable-multilib \
        --disable-newlib-supplied-syscalls \
        --enable-newlib-reent-small \
        CFLAGS_FOR_TARGET="-mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft -Os"
)

echo "=== Building newlib ==="
make -C "$OBJ_DIR" all-target-newlib

echo "=== Installing newlib into $SYSROOT ==="
make -C "$OBJ_DIR" install-target-newlib

if [ ! -f "$SYSROOT/include/stdio.h" ] || [ ! -f "$SYSROOT/lib/libc.a" ]; then
    echo "Error: expected newlib sysroot files were not produced." >&2
    echo "Missing one of:" >&2
    echo "  $SYSROOT/include/stdio.h" >&2
    echo "  $SYSROOT/lib/libc.a" >&2
    exit 1
fi

echo "Newlib sysroot ready:"
echo "  NEWLIB_SYSROOT=$SYSROOT"

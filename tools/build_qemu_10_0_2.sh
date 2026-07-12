#!/usr/bin/env bash
# Build the exact ArmOS reference QEMU release in a repo-local prefix.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QEMU_VERSION="10.0.2"
QEMU_URL="https://download.qemu.org/qemu-$QEMU_VERSION.tar.xz"
QEMU_SHA256="ef786f2398cb5184600f69aef4d5d691efd44576a3cff4126d38d4c6fec87759"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/build/qemu-$QEMU_VERSION}"
DOWNLOAD_DIR="$WORK_DIR/download"
ARCHIVE="$DOWNLOAD_DIR/qemu-$QEMU_VERSION.tar.xz"
SOURCE_DIR="$WORK_DIR/src"
BUILD_DIR="$WORK_DIR/build"
PREFIX="${PREFIX:-$WORK_DIR/install}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "error: sha256sum or shasum is required" >&2
        return 1
    fi
}

for tool in curl tar make pkg-config python3 ninja git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required host tool '$tool' not found" >&2
        exit 1
    fi
done

mkdir -p "$DOWNLOAD_DIR" "$WORK_DIR"
if [ ! -f "$ARCHIVE" ]; then
    echo "=== Downloading QEMU $QEMU_VERSION ==="
    curl -L --fail "$QEMU_URL" -o "$ARCHIVE.tmp"
    mv "$ARCHIVE.tmp" "$ARCHIVE"
fi

actual_sha256="$(sha256_file "$ARCHIVE")"
if [ "$actual_sha256" != "$QEMU_SHA256" ]; then
    echo "error: QEMU archive SHA-256 mismatch" >&2
    echo "expected: $QEMU_SHA256" >&2
    echo "actual:   $actual_sha256" >&2
    exit 1
fi
echo "QEMU archive SHA-256 verified."

if [ ! -x "$SOURCE_DIR/configure" ]; then
    echo "=== Extracting QEMU $QEMU_VERSION ==="
    rm -rf "$SOURCE_DIR"
    mkdir -p "$SOURCE_DIR"
    tar -xJf "$ARCHIVE" -C "$SOURCE_DIR" --strip-components=1
fi

mkdir -p "$BUILD_DIR" "$PREFIX"
cd "$BUILD_DIR"

echo "=== Configuring QEMU $QEMU_VERSION (arm-softmmu) ==="
"$SOURCE_DIR/configure" \
    --prefix="$PREFIX" \
    --target-list=arm-softmmu \
    --disable-docs \
    --disable-werror

echo "=== Building QEMU $QEMU_VERSION ==="
make -j"$JOBS"
make install

QEMU_BINARY="$PREFIX/bin/qemu-system-arm"
version_line="$("$QEMU_BINARY" --version | head -n 1)"
detected_version="$(printf '%s\n' "$version_line" | sed -n 's/^QEMU emulator version \([^ ]*\).*/\1/p')"
if [ "$detected_version" != "$QEMU_VERSION" ]; then
    echo "error: unexpected installed QEMU version: $version_line" >&2
    exit 1
fi

echo
echo "Installed: $QEMU_BINARY"
echo "$version_line"
echo "ArmOS boot scripts will prefer this repo-local binary automatically."

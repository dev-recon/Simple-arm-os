#!/usr/bin/env bash
#
# ArmOS
# Copyright (c) 2026 Mohamed Ennassiri
#
# Licensed under the Apache License, Version 2.0.
# See LICENSE for details.
#
# File: images/run-image.sh
# Layer: Host tooling / prebuilt image launcher
#
# Responsibilities:
# - Select an ARM32 or ARM64 QEMU Virt release image.
# - Restore prebuilt artifacts under build/images when an archive is present.
# - Launch ArmOS through boot.sh without rebuilding the kernel or userland.
#
# Notes:
# - ARM32 remains the default reference target.
# - Extra arguments are forwarded to boot.sh, including an explicit QEMU
#   binary path as its first argument.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_ARCH="${TARGET_ARCH:-arm32}"

usage()
{
    cat <<'EOF'
usage: images/run-image.sh [arm32|arm64] [QEMU_BINARY]

Launch a prebuilt ArmOS QEMU Virt image without compiling anything.

Examples:
  ./images/run-image.sh
  ./images/run-image.sh arm64
  ./images/run-image.sh arm32 /path/to/qemu-system-arm
EOF
}

case "${1:-}" in
    arm32|arm64)
        TARGET_ARCH="$1"
        shift
        ;;
    -h|--help)
        usage
        exit 0
        ;;
esac

case "$TARGET_ARCH" in
    arm32|arm64) ;;
    *)
        echo "error: unsupported architecture '$TARGET_ARCH'; expected arm32 or arm64" >&2
        exit 2
        ;;
esac

ARMOS_VERSION="$(
    awk '$1 == "ARMOS_VERSION" && $2 == ":=" { print $3; exit }' \
        "$ROOT_DIR/Makefile"
)"
if [ -z "$ARMOS_VERSION" ]; then
    echo "error: cannot read ARMOS_VERSION from $ROOT_DIR/Makefile" >&2
    exit 1
fi

ARCHIVE="$SCRIPT_DIR/ArmOS-$ARMOS_VERSION-qemu-virt-$TARGET_ARCH.tar.gz"
PUBLISHED_KERNEL="$SCRIPT_DIR/kernel-$TARGET_ARCH-qemu-virt.bin"
BUILD_IMAGE_DIR="$ROOT_DIR/build/images"
KERNEL="$BUILD_IMAGE_DIR/kernel-$TARGET_ARCH-qemu-virt.bin"
DISK="$BUILD_IMAGE_DIR/disk-$TARGET_ARCH-qemu-virt.img"

if [ ! -f "$DISK" ]; then
    if [ ! -f "$ARCHIVE" ]; then
        echo "error: prebuilt disk image not found: $DISK" >&2
        echo "error: release archive not found: $ARCHIVE" >&2
        echo "Download the $TARGET_ARCH QEMU Virt archive into images/ first." >&2
        exit 1
    fi

    echo "=== Extracting $(basename "$ARCHIVE") ==="
    mkdir -p "$BUILD_IMAGE_DIR"
    tar -xzf "$ARCHIVE" -C "$ROOT_DIR"
fi

if [ -f "$PUBLISHED_KERNEL" ]; then
    mkdir -p "$BUILD_IMAGE_DIR"
    cp "$PUBLISHED_KERNEL" "$KERNEL"
fi

if [ ! -f "$KERNEL" ]; then
    echo "error: prebuilt kernel not found: $KERNEL" >&2
    echo "Download the $TARGET_ARCH QEMU Virt kernel or archive into images/ first." >&2
    exit 1
fi

export ARMOS_CONFIG="$ROOT_DIR/configs/qemu-virt-$TARGET_ARCH.conf"
export TARGET_ARCH
export TARGET_PLATFORM=qemu-virt
export ENABLE_NET="${ENABLE_NET:-0}"
export ENABLE_GPU="${ENABLE_GPU:-0}"

echo "=== Running prebuilt ArmOS $ARMOS_VERSION $TARGET_ARCH/qemu-virt ==="
exec "$ROOT_DIR/boot.sh" "$@"

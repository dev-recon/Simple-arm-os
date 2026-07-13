#!/usr/bin/env bash
#
# ArmOS
# Copyright (c) 2026 Mohamed Ennassiri
#
# Licensed under the Apache License, Version 2.0.
# See LICENSE for details.
#
# File: tools/build_arm64_disk.sh
# Layer: Host tooling / ARM64 root filesystem
#
# Responsibilities:
# - Build a compact ext2-only QEMU disk containing AArch64 user programs.
# - Keep ARM64 binaries isolated from the stable ARM32 userfs and disk image.
#
# Notes:
# - The Raspberry Pi boot partition is intentionally absent from this QEMU
#   image; hardware images remain owned by their dedicated staging tools.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$ROOT_DIR/build/images/disk-arm64-qemu-virt.img"
ROOTFS="$ROOT_DIR/build/images/rootfs-arm64-qemu-virt.ext2"
STAGING="$ROOT_DIR/build/arm64-rootfs-staging"
ROOTFS_MB=64
EXT2_START_LBA=2048
EXT2_SECTORS=$((ROOTFS_MB * 2048))
SKIP_USERLAND=0

usage()
{
    cat <<'EOF'
usage: tools/build_arm64_disk.sh [--skip-userland] [--output FILE]

Builds a compact ext2-only QEMU disk containing the generated AArch64
hello64, hello, init, mash and initial core utilities.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-userland)
            SKIP_USERLAND=1
            ;;
        --output)
            shift
            if [ "$#" -eq 0 ]; then
                echo "error: --output requires a file" >&2
                exit 2
            fi
            OUTPUT="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$SKIP_USERLAND" -eq 0 ]; then
    "$ROOT_DIR/tools/build_arm64_userland.sh"
fi

MKE2FS="${MKE2FS:-}"
if [ -z "$MKE2FS" ]; then
    if command -v mke2fs >/dev/null 2>&1; then
        MKE2FS="$(command -v mke2fs)"
    elif command -v brew >/dev/null 2>&1; then
        MKE2FS="$(brew --prefix e2fsprogs)/sbin/mke2fs"
    fi
fi
if [ -z "$MKE2FS" ] || [ ! -x "$MKE2FS" ]; then
    echo "error: mke2fs not found (install e2fsprogs)" >&2
    exit 1
fi

HELLO64="$ROOT_DIR/build/userland-arm64/out/usr/bin/hello64"
HELLO="$ROOT_DIR/build/userland-arm64/out/usr/bin/hello"
INIT="$ROOT_DIR/build/userland-arm64/out/sbin/init"
MASH="$ROOT_DIR/build/userland-arm64/out/sbin/mash"
LS="$ROOT_DIR/build/userland-arm64/out/bin/ls"
PS="$ROOT_DIR/build/userland-arm64/out/bin/ps"
SLEEP="$ROOT_DIR/build/userland-arm64/out/bin/sleep"
PWD="$ROOT_DIR/build/userland-arm64/out/bin/pwd"
for binary in "$HELLO64" "$HELLO" "$INIT" "$MASH" \
              "$LS" "$PS" "$SLEEP" "$PWD"; do
    if [ ! -x "$binary" ]; then
        echo "error: missing AArch64 executable: $binary" >&2
        exit 1
    fi
done

rm -rf "$STAGING"
mkdir -p "$STAGING/bin" "$STAGING/usr/bin" "$STAGING/sbin" "$STAGING/dev" \
    "$STAGING/etc" "$STAGING/home/user" "$STAGING/root" "$STAGING/tmp"
cp "$HELLO64" "$STAGING/usr/bin/hello64"
cp "$HELLO" "$STAGING/usr/bin/hello"
cp "$INIT" "$STAGING/sbin/init"
cp "$MASH" "$STAGING/sbin/mash"
cp "$LS" "$STAGING/bin/ls"
cp "$PS" "$STAGING/bin/ps"
cp "$SLEEP" "$STAGING/bin/sleep"
cp "$PWD" "$STAGING/bin/pwd"
chmod 0755 "$STAGING/usr/bin/hello64" "$STAGING/usr/bin/hello" \
    "$STAGING/sbin/init" "$STAGING/sbin/mash" "$STAGING/bin/ls" \
    "$STAGING/bin/ps" "$STAGING/bin/sleep" "$STAGING/bin/pwd"
printf 'ArmOS ARM64 qemu-virt root filesystem\n' > "$STAGING/etc/motd"
chmod 1777 "$STAGING/tmp"

mkdir -p "$(dirname "$OUTPUT")" "$(dirname "$ROOTFS")"
dd if=/dev/zero of="$ROOTFS" bs=1048576 count="$ROOTFS_MB" 2>/dev/null
"$MKE2FS" -q -t ext2 -F -L ARM64_ROOT -d "$STAGING" "$ROOTFS"
dd if=/dev/zero of="$OUTPUT" bs=1048576 count=$((ROOTFS_MB + 1)) 2>/dev/null
python3 "$ROOT_DIR/tools/make_mbr.py" "$OUTPUT" \
    "$EXT2_START_LBA" "$EXT2_SECTORS" 0 0 --ext2-only
dd if="$ROOTFS" of="$OUTPUT" bs=1048576 seek=1 conv=notrunc 2>/dev/null

echo "ARM64 QEMU disk: $OUTPUT"
echo "ARM64 ext2 root: $ROOTFS"

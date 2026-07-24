#!/usr/bin/env bash
#
# ArmOS
# Copyright (c) 2026 Mohamed Ennassiri
#
# Licensed under the Apache License, Version 2.0.
# See LICENSE for details.
#
# File: tools/build_arm64_userland.sh
# Layer: Host tooling / ARM64 userland
#
# Responsibilities:
# - Build the complete generic ArmOS userland with the AArch64 newlib port.
# - Optionally install ELF64 programs into the shared userfs hierarchy.
# - Validate every generated and installed executable as AArch64 ELF64.
#
# Notes:
# - ARM32 and ARM64 intentionally use the same userland target and path sets.
# - Installing one architecture replaces generated executables in userfs; a
#   later build of the other architecture replaces them at the same paths.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/aarch64-elf}"
LIBC="$SYSROOT/lib/libc.a"
TARGETS=()
REBUILD_NEWLIB=0
CLEAN=0
INSTALL=0

usage()
{
    cat <<'EOF'
usage: tools/build_arm64_userland.sh [OPTIONS] [target ...]

Builds the AArch64 ArmOS newlib glue and userland. With no target, builds the
complete generic userland target set.

  --clean           remove previous ARM64 userland output first
  --install         build all targets and install them into shared userfs
  --rebuild-newlib  rebuild the repo-local AArch64 newlib sysroot
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --rebuild-newlib)
            REBUILD_NEWLIB=1
            ;;
        --clean)
            CLEAN=1
            ;;
        --install)
            INSTALL=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            TARGETS+=("$1")
            ;;
    esac
    shift
done

if [ "$INSTALL" -eq 1 ] && [ "${#TARGETS[@]}" -ne 0 ]; then
    echo "error: --install always installs the complete userland" >&2
    exit 2
fi
if [ "$INSTALL" -eq 1 ]; then
    TARGETS=(install)
elif [ "${#TARGETS[@]}" -eq 0 ]; then
    TARGETS=(all)
fi

if [ "$REBUILD_NEWLIB" -eq 1 ] ||
   [ ! -f "$SYSROOT/include/stdio.h" ] || [ ! -f "$LIBC" ] ||
   [ ! -f "$SYSROOT/.armos-reproducible-paths-v1" ]; then
    TARGET=aarch64-elf ARCH=aarch64-elf- \
        "$ROOT_DIR/tools/build_newlib.sh"
fi

make -C "$ROOT_DIR/newlib-port" \
    TARGET_ARCH=arm64 \
    ARCH=aarch64-elf- \
    NEWLIB_SYSROOT="$SYSROOT" \
    NEWLIB_LIBC="$LIBC"

if [ "$CLEAN" -eq 1 ]; then
    make -C "$ROOT_DIR/userland" \
        TARGET_ARCH=arm64 \
        ARCH=aarch64-elf- \
        NEWLIB_SYSROOT="$SYSROOT" \
        NEWLIB_LIBC="$LIBC" \
        clean
fi

if [ "$INSTALL" -eq 1 ]; then
    rm -f "$ROOT_DIR/build/userland-arm64/out/usr/bin/hello64"
fi

make -C "$ROOT_DIR/userland" \
    TARGET_ARCH=arm64 \
    ARCH=aarch64-elf- \
    NEWLIB_SYSROOT="$SYSROOT" \
    NEWLIB_LIBC="$LIBC" \
    "${TARGETS[@]}"

OUT_DIR="$ROOT_DIR/build/userland-arm64/out"
USERFS_DIR="$ROOT_DIR/userfs"
EXECUTABLES=0
while IFS= read -r binary; do
    if ! aarch64-elf-readelf -h "$binary" | grep -q 'Class:.*ELF64' ||
       ! aarch64-elf-readelf -h "$binary" | grep -q 'Machine:.*AArch64'; then
        echo "error: expected AArch64 ELF64 output was not produced: $binary" >&2
        exit 1
    fi
    EXECUTABLES=$((EXECUTABLES + 1))
done < <(find "$OUT_DIR" -type f | sort)

if [ "$EXECUTABLES" -eq 0 ]; then
    echo "error: no AArch64 userland executable was produced" >&2
    exit 1
fi

if [ "$INSTALL" -eq 1 ]; then
    while IFS= read -r binary; do
        relative="${binary#"$OUT_DIR"/}"
        installed="$USERFS_DIR/$relative"
        if [ ! -f "$installed" ] ||
           ! aarch64-elf-readelf -h "$installed" | grep -q 'Class:.*ELF64' ||
           ! aarch64-elf-readelf -h "$installed" | grep -q 'Machine:.*AArch64'; then
            echo "error: invalid installed AArch64 executable: $installed" >&2
            exit 1
        fi
    done < <(find "$OUT_DIR" -type f | sort)
    echo "AArch64 userland installed in shared userfs: $EXECUTABLES executables"
else
    echo "AArch64 userland ready: $EXECUTABLES executables"
fi

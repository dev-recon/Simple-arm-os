#!/usr/bin/env bash
# Build the ArmOS AArch64 newlib runtime and selected ELF64 programs.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SYSROOT="${NEWLIB_SYSROOT:-$ROOT_DIR/build/newlib-sysroot/aarch64-elf}"
LIBC="$SYSROOT/lib/libc.a"
TARGETS=()
REBUILD_NEWLIB=0

usage()
{
    cat <<'EOF'
usage: tools/build_arm64_userland.sh [--rebuild-newlib] [target ...]

Builds the AArch64 ArmOS newlib glue and selected user programs without
modifying userfs. Targets default to: hello64 hello init mash.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --rebuild-newlib)
            REBUILD_NEWLIB=1
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

if [ "${#TARGETS[@]}" -eq 0 ]; then
    TARGETS=(hello64 hello init mash)
fi

if [ "$REBUILD_NEWLIB" -eq 1 ] ||
   [ ! -f "$SYSROOT/include/stdio.h" ] || [ ! -f "$LIBC" ]; then
    TARGET=aarch64-elf ARCH=aarch64-elf- \
        "$ROOT_DIR/tools/build_newlib.sh"
fi

make -C "$ROOT_DIR/newlib-port" \
    TARGET_ARCH=arm64 \
    ARCH=aarch64-elf- \
    NEWLIB_SYSROOT="$SYSROOT" \
    NEWLIB_LIBC="$LIBC"

make -C "$ROOT_DIR/userland" \
    TARGET_ARCH=arm64 \
    ARCH=aarch64-elf- \
    NEWLIB_SYSROOT="$SYSROOT" \
    NEWLIB_LIBC="$LIBC" \
    "${TARGETS[@]}"

for target in "${TARGETS[@]}"; do
    case "$target" in
        init|mash)
            binary="$ROOT_DIR/build/userland-arm64/out/sbin/$target"
            ;;
        hello|hello64)
            binary="$ROOT_DIR/build/userland-arm64/out/usr/bin/$target"
            ;;
        *)
            continue
            ;;
    esac
    if [ ! -f "$binary" ] ||
       ! aarch64-elf-readelf -h "$binary" | grep -q 'Class:.*ELF64' ||
       ! aarch64-elf-readelf -h "$binary" | grep -q 'Machine:.*AArch64'; then
        echo "error: expected AArch64 ELF64 output was not produced: $binary" >&2
        exit 1
    fi
    echo "ELF64 ready: $binary"
done

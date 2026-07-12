#!/usr/bin/env bash
# Shared QEMU selection and optional version enforcement for host scripts.

QEMU_PINNED_VERSION="${QEMU_PINNED_VERSION:-10.0.2}"

select_arm_qemu() {
    local explicit="${1:-}"
    local root_dir="${2:?repository root is required}"
    local pinned_qemu="$root_dir/build/qemu-$QEMU_PINNED_VERSION/install/bin/qemu-system-arm"

    if [ -n "$explicit" ]; then
        printf '%s\n' "$explicit"
    elif [ -n "${QEMU:-}" ]; then
        printf '%s\n' "$QEMU"
    elif [ -x "$pinned_qemu" ]; then
        printf '%s\n' "$pinned_qemu"
    elif [ -x /opt/homebrew/bin/qemu-system-arm ]; then
        printf '%s\n' /opt/homebrew/bin/qemu-system-arm
    elif [ -x /usr/local/bin/qemu-system-arm ]; then
        printf '%s\n' /usr/local/bin/qemu-system-arm
    else
        printf '%s\n' qemu-system-arm
    fi
}

require_qemu_version() {
    local qemu_binary="${1:?QEMU binary is required}"
    local required="${QEMU_REQUIRED_VERSION:-}"
    local detected
    local version_line

    [ -n "$required" ] || return 0
    version_line="$("$qemu_binary" --version | head -n 1)"
    detected="$(printf '%s\n' "$version_line" | sed -n 's/^QEMU emulator version \([^ ]*\).*/\1/p')"
    if [ "$detected" != "$required" ]; then
        echo "Error: QEMU $required is required, found: $version_line" >&2
        echo "Run ./tools/build_qemu_10_0_2.sh or unset QEMU_REQUIRED_VERSION." >&2
        return 1
    fi
}

#!/usr/bin/env bash
# pi2_uart_screen.sh - open the Raspberry Pi 2 UART console with macOS screen.

set -euo pipefail

BAUD="${BAUD:-115200}"
UART_DEVICE="${UART_DEVICE:-}"
REATTACH="${REATTACH:-1}"

usage() {
    cat <<EOF
usage: tools/pi2_uart_screen.sh [--device /dev/cu.usbserial-XXXX] [--baud RATE]
                                [--list] [--no-reattach]

Defaults:
  baud: 115200

Environment overrides:
  UART_DEVICE, BAUD, REATTACH

Quit screen with:
  Ctrl-A then K, then y
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

list_devices() {
    local found=0

    for dev in \
        /dev/cu.usbserial* \
        /dev/cu.usbmodem* \
        /dev/cu.SLAB_USBtoUART* \
        /dev/cu.wchusbserial* \
        /dev/cu.serial* \
        /dev/tty.usbserial* \
        /dev/tty.usbmodem* \
        /dev/tty.SLAB_USBtoUART* \
        /dev/tty.wchusbserial* \
        /dev/tty.serial*
    do
        if [ -e "$dev" ]; then
            printf '%s\n' "$dev"
            found=1
        fi
    done

    return "$found"
}

list_cu_devices() {
    local found=0

    for dev in \
        /dev/cu.usbserial* \
        /dev/cu.usbmodem* \
        /dev/cu.SLAB_USBtoUART* \
        /dev/cu.wchusbserial* \
        /dev/cu.serial*
    do
        if [ -e "$dev" ]; then
            printf '%s\n' "$dev"
            found=1
        fi
    done

    return "$found"
}

list_tty_devices() {
    local found=0

    for dev in \
        /dev/tty.usbserial* \
        /dev/tty.usbmodem* \
        /dev/tty.SLAB_USBtoUART* \
        /dev/tty.wchusbserial* \
        /dev/tty.serial*
    do
        if [ -e "$dev" ]; then
            printf '%s\n' "$dev"
            found=1
        fi
    done

    return "$found"
}

detect_device() {
    local devices
    local count

    devices="$(list_cu_devices || true)"
    if [ -z "$devices" ]; then
        devices="$(list_tty_devices || true)"
    fi
    count="$(printf '%s\n' "$devices" | sed '/^$/d' | wc -l | tr -d ' ')"

    if [ "$count" = "0" ]; then
        die "no USB serial UART device found; connect the adapter or pass --device"
    fi

    if [ "$count" != "1" ]; then
        echo "multiple UART devices found:" >&2
        printf '%s\n' "$devices" >&2
        die "pass --device /dev/cu.* explicitly"
    fi

    printf '%s\n' "$devices"
}

reattach_if_screen_owns_device() {
    local pid
    local command

    if [ "$REATTACH" != "1" ] || ! command -v lsof >/dev/null 2>&1; then
        return 1
    fi

    pid="$(lsof -t "$UART_DEVICE" 2>/dev/null | head -n 1 || true)"
    if [ -z "$pid" ]; then
        return 1
    fi

    command="$(lsof -F pc "$UART_DEVICE" 2>/dev/null |
        sed -n 's/^c//p' |
        head -n 1)"
    if [ "$command" != "screen" ]; then
        if [ -z "$command" ]; then
            command="unknown"
        fi
        die "$UART_DEVICE is busy, owned by pid $pid ($command)"
    fi

    echo "=== Reattaching existing screen session ==="
    echo "device: $UART_DEVICE"
    echo "pid:    $pid"
    echo "quit:   Ctrl-A then K, then y"
    echo
    exec screen -r "$pid"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --device)
            [ "$#" -ge 2 ] || die "--device requires a path"
            UART_DEVICE="$2"
            shift 2
            ;;
        --baud)
            [ "$#" -ge 2 ] || die "--baud requires a rate"
            BAUD="$2"
            shift 2
            ;;
        --list)
            list_devices || true
            exit 0
            ;;
        --no-reattach)
            REATTACH=0
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

command -v screen >/dev/null 2>&1 || die "screen not found"

if [ -z "$UART_DEVICE" ]; then
    UART_DEVICE="$(detect_device)"
fi

[ -e "$UART_DEVICE" ] || die "UART device not found: $UART_DEVICE"

reattach_if_screen_owns_device || true

echo "=== Opening ArmOS Raspberry Pi 2 UART console ==="
echo "device: $UART_DEVICE"
echo "baud:   $BAUD"
echo "quit:   Ctrl-A then K, then y"
echo

exec screen "$UART_DEVICE" "$BAUD"

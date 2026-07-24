#!/usr/bin/env bash
#
# ArmOS Raspberry Pi 3 B+ Wi-Fi firmware installer.
#
# The CYW43455 firmware is not part of ArmOS and is not covered by the ArmOS
# Apache-2.0 license. This script downloads a pinned upstream revision only
# after the user explicitly accepts the separate Cypress/Broadcom terms.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST_DIR="$ROOT_DIR/userfs/lib/firmware/brcm"
ACCEPT_LICENSE=0

FIRMWARE_REVISION="c9d3ae6584ab79d19a4f94ccf701e888f9f87a53"
FIRMWARE_BASE="https://github.com/RPi-Distro/firmware-nonfree/raw/$FIRMWARE_REVISION/debian/config/brcm80211"
LICENSE_URL="https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/LICENCE.broadcom_bcm43xx"

usage() {
    cat <<EOF
Usage: $0 --accept-license [--dest DIRECTORY]

Download the Raspberry Pi 3 B+ CYW43455 firmware files required by the
ArmOS Wi-Fi profile. The files are installed under:

  $DEST_DIR

The firmware is separately licensed by Cypress/Broadcom and is not
distributed by ArmOS. Review its license before accepting:

  $LICENSE_URL

Options:
  --accept-license   Confirm acceptance of the separate firmware license
  --dest DIRECTORY  Override the installation directory
  -h, --help         Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --accept-license)
            ACCEPT_LICENSE=1
            ;;
        --dest)
            [ "$#" -ge 2 ] || { echo "error: --dest requires a directory" >&2; exit 2; }
            DEST_DIR="$2"
            shift
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

if [ "$ACCEPT_LICENSE" -ne 1 ]; then
    echo "error: firmware license acceptance is required" >&2
    echo "review: $LICENSE_URL" >&2
    echo "rerun with --accept-license to download the files" >&2
    exit 2
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "error: sha256sum or shasum is required" >&2
    exit 1
fi

download() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -L --fail --silent --show-error "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
    else
        echo "error: curl or wget is required" >&2
        return 1
    fi
}

install_firmware() {
    local output_name="$1"
    local source_path="$2"
    local expected_hash="$3"
    local destination="$DEST_DIR/$output_name"
    local temporary="$TMP_DIR/$output_name"
    local actual_hash

    if [ -f "$destination" ]; then
        actual_hash="$(sha256_file "$destination")"
        if [ "$actual_hash" = "$expected_hash" ]; then
            echo "verified: $destination"
            return 0
        fi
    fi

    echo "download: $output_name"
    download "$FIRMWARE_BASE/$source_path" "$temporary"
    actual_hash="$(sha256_file "$temporary")"
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "error: SHA-256 mismatch for $output_name" >&2
        echo "expected: $expected_hash" >&2
        echo "actual:   $actual_hash" >&2
        return 1
    fi
    install -m 0644 "$temporary" "$destination"
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/armos-wifi.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
mkdir -p "$DEST_DIR"

echo "=== ArmOS Raspberry Pi 3 B+ Wi-Fi firmware ==="
echo "revision: $FIRMWARE_REVISION"
echo "target:   $DEST_DIR"

install_firmware \
    "brcmfmac43455-sdio.bin" \
    "cypress/cyfmac43455-sdio-minimal.bin" \
    "3075cb0bdc4b28ed4f08e01b1a216d0ebc70f4022d9d3272a4a43b3c90456e60"
install_firmware \
    "brcmfmac43455-sdio.txt" \
    "brcm/brcmfmac43455-sdio.txt" \
    "ca709be81a78bdb6932936374f39943acbd7af07fae6151011127599a3ce9e3d"
install_firmware \
    "brcmfmac43455-sdio.clm_blob" \
    "cypress/cyfmac43455-sdio.clm_blob" \
    "9823842cae9fb9a5dd1e5fb31f595516ec7deee341354bef30bb3026eee29cc1"

echo "Wi-Fi firmware installed. Rebuild the raspi3 Wi-Fi disk image."

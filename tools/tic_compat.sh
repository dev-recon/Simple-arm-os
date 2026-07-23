#!/usr/bin/env bash
#
# Compatibility wrapper for Apple's ncurses 6.0 tic.

set -euo pipefail

HOST_TIC="${ARMOS_HOST_TIC:-/usr/bin/tic}"
ARGS=()

for arg in "$@"; do
    if [ "$arg" != "-x" ]; then
        ARGS+=("$arg")
    fi
done

exec "$HOST_TIC" "${ARGS[@]}"

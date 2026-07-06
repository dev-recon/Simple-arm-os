#!/usr/bin/env bash
# Shared QEMU platform loader for ArmOS boot scripts.
#
# The caller must define ROOT_DIR before sourcing this file.

if [ -z "${ROOT_DIR:-}" ]; then
    echo "Error: ROOT_DIR must be set before sourcing qemu_platform_env.sh"
    exit 1
fi

TARGET_ARCH="${TARGET_ARCH:-arm32}"
TARGET_PLATFORM="${TARGET_PLATFORM:-qemu-virt}"
TARGET_PLATFORM_DIR="${TARGET_PLATFORM//-/_}"
QEMU_PLATFORM_ENV="$ROOT_DIR/arch/${TARGET_ARCH}/platform/${TARGET_PLATFORM_DIR}/qemu.sh"

if [ ! -f "$QEMU_PLATFORM_ENV" ]; then
    echo "Error: unsupported QEMU platform '${TARGET_ARCH}/${TARGET_PLATFORM}'"
    echo "Missing: ${QEMU_PLATFORM_ENV}"
    exit 1
fi

# shellcheck source=/dev/null
. "$QEMU_PLATFORM_ENV"

QEMU_MACHINE="${QEMU_MACHINE:-${QEMU_MACHINE_DEFAULT:-virt}}"
QEMU_CPU="${QEMU_CPU:-${QEMU_CPU_DEFAULT:-cortex-a15}}"
QEMU_BLOCK_DEVICE="${QEMU_BLOCK_DEVICE:-${QEMU_BLOCK_DEVICE_DEFAULT:-virtio-blk-device,drive=hd0}}"
QEMU_GPU_DEVICE="${QEMU_GPU_DEVICE:-${QEMU_GPU_DEVICE_DEFAULT:-virtio-gpu-device}}"
QEMU_INPUT_DEVICE="${QEMU_INPUT_DEVICE:-${QEMU_INPUT_DEVICE_DEFAULT:-virtio-keyboard-device}}"
QEMU_NET_DEVICE_MODEL="${QEMU_NET_DEVICE_MODEL:-${QEMU_NET_DEVICE_MODEL_DEFAULT:-virtio-net-device}}"

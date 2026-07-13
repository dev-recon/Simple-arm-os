#!/usr/bin/env bash
# QEMU launch defaults for the ARM64 qemu-virt platform.

QEMU_MACHINE_DEFAULT="virt,gic-version=2"
QEMU_CPU_DEFAULT="cortex-a72"
QEMU_MEMORY_DEFAULT="1G"
QEMU_SMP_DEFAULT="1"
QEMU_BLOCK_ENABLED_DEFAULT="1"
QEMU_KERNEL_IMAGE_DEFAULT="$ROOT_DIR/build/images/kernel-arm64-qemu-virt.bin"
QEMU_DISK_IMAGE_DEFAULT="$ROOT_DIR/build/images/disk-arm64-qemu-virt.img"
QEMU_GPU_DEVICE_DEFAULT=""
QEMU_INPUT_DEVICE_DEFAULT=""
QEMU_NET_DEVICE_MODEL_DEFAULT=""

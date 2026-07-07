#!/usr/bin/env bash
# QEMU launch defaults for the ARM32 Raspberry Pi 2 platform.

QEMU_MACHINE_DEFAULT="raspi2b"
QEMU_CPU_DEFAULT="cortex-a7"
QEMU_MEMORY_DEFAULT="1G"
# QEMU's raspi2b machine models the real BCM2836 as a four-core board and
# rejects lower -smp values. The early raspi2 bring-up may still keep the
# kernel scheduler conservative; this only satisfies the board model.
QEMU_SMP_DEFAULT="4"
QEMU_BLOCK_ENABLED_DEFAULT="1"
QEMU_BLOCK_IF_DEFAULT="sd"
QEMU_KERNEL_LOADER_ADDR_DEFAULT="0x02010000"
QEMU_BLOCK_DEVICE_DEFAULT=""
QEMU_GPU_DEVICE_DEFAULT=""
QEMU_INPUT_DEVICE_DEFAULT=""
QEMU_NET_DEVICE_MODEL_DEFAULT=""

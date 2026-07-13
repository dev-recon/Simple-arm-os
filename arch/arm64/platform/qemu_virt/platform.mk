# ArmOS ARM64 QEMU virt platform.

PLATFORM_CFLAGS = -mcpu=cortex-a72 -DARMOS_PLATFORM_QEMU_VIRT
PLATFORM_ASFLAGS = -mcpu=cortex-a72
PLATFORM_LDFLAGS =
STACK_PROTECTOR_FLAG = -fno-stack-protector
LINKER_SCRIPT = $(ARCH_DIR)/linker.ld
IMAGE_SUFFIX = arm64-qemu-virt

PLATFORM_OBJS = $(PLATFORM_DIR)/virtio_block.o

QEMU_MACHINE ?= virt,gic-version=2
QEMU_CPU ?= cortex-a72

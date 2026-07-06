# ArmOS ARM32 qemu-virt platform fragment.
#
# The top-level Makefile includes one platform fragment after selecting
# TARGET_ARCH. Keep machine-specific CPU flags, platform objects, and QEMU
# defaults here so a second ARM32 board can add its own fragment without
# growing conditionals in the root build.

PLATFORM_CPU_CFLAGS = -mcpu=cortex-a15
PLATFORM_CFLAGS = $(PLATFORM_CPU_CFLAGS) -DARMOS_PLATFORM_QEMU_VIRT

PLATFORM_OBJS = \
	$(PLATFORM_DIR)/devices.o \
	kernel/drivers/ata.o \
	kernel/drivers/keyboard.o \
	kernel/drivers/display.o \
	kernel/drivers/virtio_gpu.o \
	kernel/drivers/virtio_input.o \
	kernel/drivers/virtio_net.o \
	kernel/drivers/ide.o \
	kernel/drivers/virtio_block.o \
	$(ARCH_DIR)/interrupt/gic.o \
	$(ARCH_DIR)/power/psci.o

QEMU_MACHINE ?= virt
QEMU_RUN_MACHINE ?= virt,highmem=off
QEMU_CPU ?= cortex-a15

# ArmOS ARM32 Raspberry Pi 2 platform fragment.
#
# First milestone: QEMU raspi2b UART-only boot. Platform init only advertises
# devices that exist on this board.

PLATFORM_CPU_CFLAGS = -mcpu=cortex-a7
PLATFORM_CFLAGS = $(PLATFORM_CPU_CFLAGS) -DARMOS_PLATFORM_RASPI2
PLATFORM_LDFLAGS = \
	--defsym=KERNEL_LINK_ADDR=0x02010000 \
	--defsym=RAM_BASE_ADDR=0x00000000 \
	--defsym=RAM_END_ADDR=0x3F000000

# QEMU raspi2b models the SD card strictly and rejects raw images whose size is
# not a power of two.  The MBR partition layout remains 577 MiB; the platform
# image is padded to a 1 GiB card.
PLATFORM_DISK_SIZE_MB ?= 1024

PLATFORM_OBJS = \
	$(PLATFORM_DIR)/devices.o \
	$(PLATFORM_DIR)/irq.o \
	$(PLATFORM_DIR)/power.o \
	kernel/drivers/mmc/bcm2835_emmc.o \
	kernel/drivers/keyboard.o \
	kernel/drivers/display.o \
	kernel/drivers/virtio_gpu.o \
	kernel/drivers/virtio_input.o \
	kernel/drivers/virtio_net.o \
	kernel/drivers/virtio_block.o

QEMU_MACHINE ?= raspi2b
QEMU_RUN_MACHINE ?= raspi2b
QEMU_CPU ?= cortex-a7
QEMU_BOOT_DRIVE ?= -drive file=$(PLATFORM_DISK_IMG),if=sd,format=raw
QEMU_BOOT_DEVICE ?=
QEMU_MMIO_DRIVE ?=
QEMU_MMIO_DEVICE ?=
QEMU_DEBUG_DEVICE ?=
QEMU_SIMPLE_DRIVE ?= -drive file=$(PLATFORM_DISK_IMG),if=sd,format=raw

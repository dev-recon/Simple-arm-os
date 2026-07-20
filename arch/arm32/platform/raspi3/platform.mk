# ArmOS ARM32 Raspberry Pi 3 hardware platform fragment.
#
# This profile is for real Raspberry Pi 3 boards running kernel7.img in
# AArch32. QEMU raspi2b remains TARGET_PLATFORM=raspi2 so emulator quirks do
# not leak into hardware bring-up.

PLATFORM_CPU_CFLAGS = -mcpu=cortex-a53
PLATFORM_CFLAGS = $(PLATFORM_CPU_CFLAGS) -DARMOS_PLATFORM_RASPI3 -DARMOS_PLATFORM_RASPBERRYPI
PLATFORM_ASFLAGS = -march=armv8-a --defsym ARMOS_PLATFORM_RASPI3=1 --defsym ARMOS_PLATFORM_RASPBERRYPI=1
PLATFORM_LDFLAGS = \
	--defsym=KERNEL_LINK_ADDR=0x02010000 \
	--defsym=RAM_BASE_ADDR=0x00000000 \
	--defsym=RAM_END_ADDR=0x3F000000

PLATFORM_DISK_SIZE_MB ?= 1024
PLATFORM_DISK_LAYOUT ?= fat32-first
# Pi 3 firmware and macOS both require a standard FAT32 LBA partition type.
PLATFORM_DISK_HIDDEN_BOOT ?= 0

RASPBERRYPI_PLATFORM_DIR = kernel/platform/raspberrypi
ENABLE_HDMI ?= 0
ENABLE_USB ?= 0
HDMI_WIDTH ?= 1280
HDMI_HEIGHT ?= 720
ENABLE_ILI9341 ?= 1
PLATFORM_OBJS = \
	$(RASPBERRYPI_PLATFORM_DIR)/devices.o \
	$(RASPBERRYPI_PLATFORM_DIR)/irq.o \
	$(RASPBERRYPI_PLATFORM_DIR)/mailbox.o \
	$(RASPBERRYPI_PLATFORM_DIR)/power.o \
	kernel/drivers/mmc/bcm2835_emmc.o \
	kernel/drivers/keyboard.o \
	kernel/drivers/display.o \
	kernel/drivers/virtio_input.o \
	kernel/drivers/virtio_net.o \
	kernel/drivers/virtio_block.o

ifneq ($(filter 1 yes true on,$(ENABLE_HDMI)),)
PLATFORM_CFLAGS += -DARMOS_ENABLE_HDMI \
	-DARMOS_HDMI_WIDTH=$(HDMI_WIDTH) -DARMOS_HDMI_HEIGHT=$(HDMI_HEIGHT)
PLATFORM_OBJS += kernel/drivers/video/raspberrypi_hdmi.o
endif

ifneq ($(filter 1 yes true on,$(ENABLE_USB)),)
PLATFORM_CFLAGS += -DARMOS_ENABLE_USB
PLATFORM_OBJS += kernel/drivers/usb/dwc2.o
endif

ifneq ($(filter 1 yes true on,$(ENABLE_ILI9341)),)
PLATFORM_CFLAGS += -DARMOS_ENABLE_ILI9341
PLATFORM_OBJS += \
	kernel/drivers/gpio/bcm283x_gpio.o \
	kernel/drivers/gpio/gpio_parallel8.o \
	kernel/drivers/video/ili9341.o
endif

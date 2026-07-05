ARCH ?= arm-none-eabi-
CC := $(ARCH)gcc
AS := $(ARCH)as

ARCH_FLAGS := -mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft
BUILD_DIR := build

NEWLIB_SYSROOT ?= $(shell $(CC) -print-sysroot 2>/dev/null)
NEWLIB_INCLUDE ?= $(NEWLIB_SYSROOT)/include
NEWLIB_LIBC ?= $(shell $(CC) $(ARCH_FLAGS) --sysroot=$(NEWLIB_SYSROOT) -print-file-name=libc.a 2>/dev/null)

CFLAGS := $(ARCH_FLAGS) -std=gnu99 -ffreestanding -nostdlib -fno-builtin \
          -fno-stack-protector -ffunction-sections -fdata-sections \
          -Os -I../userland/include -I$(NEWLIB_INCLUDE)
ASFLAGS := -mcpu=cortex-a15

OBJECTS := $(BUILD_DIR)/crt0_newlib.o \
           $(BUILD_DIR)/syscall_raw.o \
           $(BUILD_DIR)/syscalls.o

.PHONY: all clean check-newlib

all: check-newlib $(OBJECTS)

check-newlib:
	@if [ -z "$(NEWLIB_SYSROOT)" ] || [ ! -f "$(NEWLIB_INCLUDE)/stdio.h" ] || [ ! -f "$(NEWLIB_LIBC)" ]; then \
		echo "Error: newlib sysroot not found or incomplete."; \
		echo "Set NEWLIB_SYSROOT to a sysroot containing include/stdio.h and libc.a."; \
		echo "Example: make -C newlib-port NEWLIB_SYSROOT=/path/to/arm-os-sysroot"; \
		echo "Detected NEWLIB_SYSROOT=$(NEWLIB_SYSROOT)"; \
		echo "Detected NEWLIB_LIBC=$(NEWLIB_LIBC)"; \
		exit 1; \
	fi

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(BUILD_DIR)

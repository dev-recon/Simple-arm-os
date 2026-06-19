COREUTILS := cat echo pwd true false rm touch write mkdir rmdir sleep kill ls cp mv ps lps stat shutdown memstress chmod chown ln readlink head tail wc grep sed sort uniq basename dirname env printf date df du sync find cmp tee uptime free uname killall whoami who mount mount-fat32 umount which keytest ttytest ttyinfo screen_demo kilo dmesg fsck-lite
PROGRAMS := nl-hello nl-systest nl-init nl-mash $(COREUTILS:%=nl-%)
UNPREFIXED_LINKS := nl-systest nl-init nl-mash $(COREUTILS:%=nl-%)
ARCH ?= arm-none-eabi-
CC := $(ARCH)gcc
STRIP := $(ARCH)strip

BUILD_DIR := ../../build/newlib-tests
NEWLIB_PORT := ../../newlib-port
USERFS_ROOT := ../../userfs
USERFS_BIN := $(USERFS_ROOT)/bin
USERFS_SBIN := $(USERFS_ROOT)/sbin
USERFS_NEWLIB_BIN := $(USERFS_ROOT)/opt/newlib/bin
USERFS_NEWLIB_SBIN := $(USERFS_ROOT)/opt/newlib/sbin

ARCH_FLAGS := -mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft
NEWLIB_SYSROOT ?= $(shell $(CC) -print-sysroot 2>/dev/null)
NEWLIB_LIBC ?= $(NEWLIB_SYSROOT)/lib/libc.a
LIBGCC := $(shell $(CC) $(ARCH_FLAGS) -print-libgcc-file-name 2>/dev/null)

CFLAGS := $(ARCH_FLAGS) -std=gnu99 -Os -ffreestanding -fno-builtin \
          -ffunction-sections -fdata-sections \
          -fno-stack-protector -DARM_OS_NEWLIB -Iinclude -I$(NEWLIB_SYSROOT)/include
LDFLAGS := $(ARCH_FLAGS) -nostdlib -nostartfiles -static \
           -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections \
           -Wl,--allow-multiple-definition

PORT_OBJECTS := $(NEWLIB_PORT)/build/crt0_newlib.o \
                $(NEWLIB_PORT)/build/syscall_raw.o \
                $(NEWLIB_PORT)/build/syscalls.o

HELLO_OBJECTS := $(BUILD_DIR)/hello/main.o
SYSTEST_OBJECTS := $(BUILD_DIR)/systest/systest.o
INIT_OBJECTS := $(BUILD_DIR)/init/main.o
MASH_SOURCES := $(wildcard mash/src/*.c)
MASH_OBJECTS := $(MASH_SOURCES:mash/src/%.c=$(BUILD_DIR)/mash/%.o)
COREUTILS_OBJECTS := $(COREUTILS:%=$(BUILD_DIR)/coreutils/%.o)

.PHONY: all clean install check-newlib newlib-port

all: check-newlib $(PROGRAMS)

check-newlib:
	@if [ -z "$(NEWLIB_SYSROOT)" ] || [ ! -f "$(NEWLIB_SYSROOT)/include/stdio.h" ] || [ ! -f "$(NEWLIB_LIBC)" ]; then \
		echo "Error: newlib sysroot not found or incomplete."; \
		echo "Set NEWLIB_SYSROOT to a sysroot containing include/stdio.h and libc.a."; \
		echo "Detected NEWLIB_SYSROOT=$(NEWLIB_SYSROOT)"; \
		echo "Detected NEWLIB_LIBC=$(NEWLIB_LIBC)"; \
		exit 1; \
	fi

newlib-port:
	$(MAKE) -C $(NEWLIB_PORT) ARCH="$(ARCH)" NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)" NEWLIB_LIBC="$(NEWLIB_LIBC)"

$(BUILD_DIR)/hello $(BUILD_DIR)/systest $(BUILD_DIR)/init $(BUILD_DIR)/mash $(BUILD_DIR)/coreutils:
	mkdir -p $@

$(BUILD_DIR)/hello/%.o: hello/%.c | $(BUILD_DIR)/hello
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/systest/%.o: systest/%.c | $(BUILD_DIR)/systest
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/init/%.o: init/%.c | $(BUILD_DIR)/init
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/mash/%.o: mash/src/%.c | $(BUILD_DIR)/mash
	$(CC) $(CFLAGS) -Imash/include -c $< -o $@

$(BUILD_DIR)/coreutils/%.o: ../coreutils/src/%.c | $(BUILD_DIR)/coreutils
	$(CC) $(CFLAGS) -include arm_os_abi.h -c $< -o $@

nl-hello: newlib-port $(HELLO_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(HELLO_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-systest: newlib-port $(SYSTEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(SYSTEST_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-init: newlib-port $(INIT_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(INIT_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-mash: newlib-port $(MASH_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(MASH_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-%: newlib-port $(BUILD_DIR)/coreutils/%.o
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(BUILD_DIR)/coreutils/$*.o "$(NEWLIB_LIBC)" "$(LIBGCC)"

install: $(PROGRAMS)
	mkdir -p $(USERFS_BIN) $(USERFS_SBIN) $(USERFS_NEWLIB_BIN) $(USERFS_NEWLIB_SBIN)
	@for prog in $(PROGRAMS); do \
		name=$${prog#nl-}; \
		if [ "$$name" = "init" ]; then \
			cp $$prog $(USERFS_NEWLIB_SBIN)/$$prog; \
			cp $$prog $(USERFS_SBIN)/$$name; \
			rm -f $(USERFS_BIN)/$$name $(USERFS_NEWLIB_BIN)/$$prog; \
			$(STRIP) --strip-all $(USERFS_NEWLIB_SBIN)/$$prog $(USERFS_SBIN)/$$name; \
		else \
			cp $$prog $(USERFS_NEWLIB_BIN)/$$prog; \
			cp $$prog $(USERFS_BIN)/$$name; \
			$(STRIP) --strip-all $(USERFS_NEWLIB_BIN)/$$prog $(USERFS_BIN)/$$name; \
		fi; \
	done

clean:
	rm -rf $(BUILD_DIR) $(PROGRAMS)

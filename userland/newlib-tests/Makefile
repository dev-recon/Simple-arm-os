COREUTILS := cat echo pwd true false rm touch write mkdir rmdir sleep kill ls cp mv ps lps stat shutdown memstress chmod chown ln head grep which keytest ttytest ttyinfo screen_demo kilo
PROGRAMS := nl-hello nl-systest nl-mash $(COREUTILS:%=nl-%)
UNPREFIXED_LINKS := nl-systest nl-mash $(COREUTILS:%=nl-%)
ARCH ?= arm-none-eabi-
CC := $(ARCH)gcc

BUILD_DIR := ../../build/newlib-tests
NEWLIB_PORT := ../../newlib-port
USERFS_ROOT := ../../userfs
USERFS_USR_BIN := $(USERFS_ROOT)/usr/bin
USERFS_NEWLIB_BIN := $(USERFS_ROOT)/opt/newlib/bin

ARCH_FLAGS := -mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft
NEWLIB_SYSROOT ?= $(shell $(CC) -print-sysroot 2>/dev/null)
NEWLIB_LIBC ?= $(NEWLIB_SYSROOT)/lib/libc.a
LIBGCC := $(shell $(CC) $(ARCH_FLAGS) -print-libgcc-file-name 2>/dev/null)

CFLAGS := $(ARCH_FLAGS) -std=gnu99 -Os -g -ffreestanding -fno-builtin \
          -fno-stack-protector -DARM_OS_NEWLIB -Iinclude -I$(NEWLIB_SYSROOT)/include
LDFLAGS := $(ARCH_FLAGS) -nostdlib -nostartfiles -static \
           -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections \
           -Wl,--allow-multiple-definition

PORT_OBJECTS := $(NEWLIB_PORT)/build/crt0_newlib.o \
                $(NEWLIB_PORT)/build/syscall_raw.o \
                $(NEWLIB_PORT)/build/syscalls.o

HELLO_OBJECTS := $(BUILD_DIR)/hello/main.o
SYSTEST_OBJECTS := $(BUILD_DIR)/systest/systest.o
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
	$(MAKE) -C $(NEWLIB_PORT) NEWLIB_SYSROOT="$(NEWLIB_SYSROOT)"

$(BUILD_DIR)/hello $(BUILD_DIR)/systest $(BUILD_DIR)/mash $(BUILD_DIR)/coreutils:
	mkdir -p $@

$(BUILD_DIR)/hello/%.o: hello/%.c | $(BUILD_DIR)/hello
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/systest/%.o: systest/%.c | $(BUILD_DIR)/systest
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/mash/%.o: mash/src/%.c | $(BUILD_DIR)/mash
	$(CC) $(CFLAGS) -Imash/include -c $< -o $@

$(BUILD_DIR)/coreutils/%.o: ../coreutils/src/%.c | $(BUILD_DIR)/coreutils
	$(CC) $(CFLAGS) -include arm_os_abi.h -c $< -o $@

nl-hello: newlib-port $(HELLO_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(HELLO_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-systest: newlib-port $(SYSTEST_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(SYSTEST_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-mash: newlib-port $(MASH_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(MASH_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-%: newlib-port $(BUILD_DIR)/coreutils/%.o
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(BUILD_DIR)/coreutils/$*.o "$(NEWLIB_LIBC)" "$(LIBGCC)"

install: $(PROGRAMS)
	mkdir -p $(USERFS_USR_BIN) $(USERFS_NEWLIB_BIN)
	@for prog in $(PROGRAMS); do \
		cp $$prog $(USERFS_NEWLIB_BIN)/$$prog; \
		ln -sfn ../../opt/newlib/bin/$$prog $(USERFS_USR_BIN)/$$prog; \
		case " $(UNPREFIXED_LINKS) " in \
			*" $$prog "*) \
				name=$${prog#nl-}; \
				ln -sfn ../../opt/newlib/bin/$$prog $(USERFS_USR_BIN)/$$name; \
				;; \
		esac; \
	done

clean:
	rm -rf $(BUILD_DIR) $(PROGRAMS)

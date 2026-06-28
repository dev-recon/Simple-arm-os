# ArmOS userland build.
#
# Newlib is the supported userspace ABI. Legacy home-grown libc sources are
# kept under userland/legacy for reference only.

ARCH ?= arm-none-eabi-
CC := $(ARCH)gcc
STRIP := $(ARCH)strip

BUILD_DIR := ../build/userland
NEWLIB_PORT := ../newlib-port
USERFS_ROOT := ../userfs
USERFS_BIN := $(USERFS_ROOT)/bin
USERFS_SBIN := $(USERFS_ROOT)/sbin
USERFS_USR_BIN := $(USERFS_ROOT)/usr/bin
USERFS_OPT := $(USERFS_ROOT)/opt

ARCH_FLAGS := -mcpu=cortex-a15 -marm -mfpu=neon-vfpv4 -mfloat-abi=soft
NEWLIB_SYSROOT ?= $(shell $(CC) -print-sysroot 2>/dev/null)
NEWLIB_LIBC ?= $(NEWLIB_SYSROOT)/lib/libc.a
LIBGCC := $(shell $(CC) $(ARCH_FLAGS) -print-libgcc-file-name 2>/dev/null)

CFLAGS := $(ARCH_FLAGS) -std=gnu99 -Os -ffreestanding -fno-builtin \
          -ffunction-sections -fdata-sections \
          -fno-stack-protector -DARM_OS_NEWLIB \
          -Iinclude -I$(NEWLIB_SYSROOT)/include
LDFLAGS := $(ARCH_FLAGS) -nostdlib -nostartfiles -static \
           -Wl,-Ttext=0x8000 -Wl,-e,_start -Wl,--gc-sections \
           -Wl,--allow-multiple-definition

PORT_OBJECTS := $(NEWLIB_PORT)/build/crt0_newlib.o \
                $(NEWLIB_PORT)/build/syscall_raw.o \
                $(NEWLIB_PORT)/build/syscalls.o

COREUTIL_SRCS := $(wildcard coreutils/src/*.c)
COREUTILS := $(sort $(patsubst coreutils/src/%.c,%,$(COREUTIL_SRCS)))
COREUTIL_TARGETS := $(COREUTILS:%=nl-%)

SYSTEM_TOOL_SRCS := $(wildcard system/tools/*.c)
SYSTEM_TOOLS := $(sort $(patsubst system/tools/%.c,%,$(SYSTEM_TOOL_SRCS)))
SYSTEM_TOOL_TARGETS := $(SYSTEM_TOOLS:%=nl-%)

PROGRAM_DIRS := $(sort $(dir $(wildcard programs/*/*.c)))
PROGRAMS := $(patsubst programs/%/,%,$(PROGRAM_DIRS))

EXTERNAL_DIRS := $(sort $(dir $(wildcard opt/*/src/*.c)))
EXTERNALS := $(patsubst opt/%/src/,%,$(EXTERNAL_DIRS))

EXTERNALS := $(filter-out tcc,$(EXTERNALS))

ifneq ($(ENABLE_TCC),1)
PROGRAMS := $(filter-out tcc,$(PROGRAMS))
endif

PROGRAM_TARGETS := $(PROGRAMS:%=nl-%)
EXTERNAL_TARGETS := $(EXTERNALS:%=nl-%)

SYSTEM_TARGETS := nl-init nl-mash $(SYSTEM_TOOL_TARGETS)
TARGETS := $(SYSTEM_TARGETS) $(COREUTIL_TARGETS) $(PROGRAM_TARGETS) $(EXTERNAL_TARGETS)

MASH_SRCS := $(wildcard system/mash/src/*.c)
MASH_OBJECTS := $(patsubst system/mash/src/%.c,$(BUILD_DIR)/system/mash/%.o,$(MASH_SRCS))
INIT_SRCS := $(wildcard system/init/*.c)
INIT_OBJECTS := $(patsubst system/init/%.c,$(BUILD_DIR)/system/init/%.o,$(INIT_SRCS))

.PHONY: all clean install check-newlib newlib-port list

all: check-newlib $(TARGETS)

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

list:
	@printf '%s\n' $(TARGETS)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/coreutils/%.o: coreutils/src/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -include arm_os_abi.h -c $< -o $@

$(BUILD_DIR)/system/tools/%.o: system/tools/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -include arm_os_abi.h -c $< -o $@

$(BUILD_DIR)/programs/%.o: programs/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/opt/%.o: opt/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/system/init/%.o: system/init/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/system/mash/%.o: system/mash/src/%.c | $(BUILD_DIR)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -Isystem/mash/include -c $< -o $@

define PROGRAM_RULE
$(1)_SRCS := $$(wildcard programs/$(1)/*.c)
$(1)_OBJECTS := $$(patsubst programs/$(1)/%.c,$$(BUILD_DIR)/programs/$(1)/%.o,$$($(1)_SRCS))

nl-$(1): newlib-port $$($(1)_OBJECTS)
	$$(CC) $$(LDFLAGS) -o $$@ $$(PORT_OBJECTS) $$($(1)_OBJECTS) "$$(NEWLIB_LIBC)" "$$(LIBGCC)"
endef

$(foreach prog,$(PROGRAMS),$(eval $(call PROGRAM_RULE,$(prog))))

define EXTERNAL_RULE
$(1)_EXTERNAL_SRCS := $$(wildcard opt/$(1)/src/*.c)
$(1)_EXTERNAL_OBJECTS := $$(patsubst opt/%.c,$$(BUILD_DIR)/opt/%.o,$$($(1)_EXTERNAL_SRCS))

nl-$(1): newlib-port $$($(1)_EXTERNAL_OBJECTS)
	$$(CC) $$(LDFLAGS) -o $$@ $$(PORT_OBJECTS) $$($(1)_EXTERNAL_OBJECTS) "$$(NEWLIB_LIBC)" "$$(LIBGCC)"
endef

$(foreach prog,$(EXTERNALS),$(eval $(call EXTERNAL_RULE,$(prog))))

nl-init: newlib-port $(INIT_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(INIT_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-mash: newlib-port $(MASH_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(MASH_OBJECTS) "$(NEWLIB_LIBC)" "$(LIBGCC)"

$(SYSTEM_TOOL_TARGETS): nl-%: newlib-port $(BUILD_DIR)/system/tools/%.o
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(BUILD_DIR)/system/tools/$*.o "$(NEWLIB_LIBC)" "$(LIBGCC)"

nl-%: newlib-port $(BUILD_DIR)/coreutils/%.o
	$(CC) $(LDFLAGS) -o $@ $(PORT_OBJECTS) $(BUILD_DIR)/coreutils/$*.o "$(NEWLIB_LIBC)" "$(LIBGCC)"

install: $(TARGETS)
	mkdir -p $(USERFS_BIN) $(USERFS_SBIN) $(USERFS_USR_BIN) $(USERFS_OPT)
	rm -rf $(USERFS_ROOT)/opt/newlib
	@for name in init mash; do \
		cp nl-$$name $(USERFS_SBIN)/$$name; \
		rm -f $(USERFS_BIN)/$$name $(USERFS_USR_BIN)/$$name; \
		$(STRIP) --strip-all $(USERFS_SBIN)/$$name; \
	done
	@for name in $(SYSTEM_TOOLS); do \
		cp nl-$$name $(USERFS_SBIN)/$$name; \
		rm -f $(USERFS_BIN)/$$name $(USERFS_USR_BIN)/$$name; \
		rm -f $(USERFS_OPT)/$$name/bin/$$name; \
		$(STRIP) --strip-all $(USERFS_SBIN)/$$name; \
	done
	@for name in $(COREUTILS); do \
		cp nl-$$name $(USERFS_BIN)/$$name; \
		rm -f $(USERFS_SBIN)/$$name $(USERFS_USR_BIN)/$$name; \
		rm -f $(USERFS_OPT)/$$name/bin/$$name; \
		$(STRIP) --strip-all $(USERFS_BIN)/$$name; \
	done
	@for name in $(PROGRAMS); do \
		cp nl-$$name $(USERFS_USR_BIN)/$$name; \
		rm -f $(USERFS_BIN)/$$name $(USERFS_SBIN)/$$name; \
		rm -f $(USERFS_OPT)/$$name/bin/$$name; \
		$(STRIP) --strip-all $(USERFS_USR_BIN)/$$name; \
	done
	@for name in $(EXTERNALS); do \
		mkdir -p $(USERFS_OPT)/$$name/bin; \
		cp nl-$$name $(USERFS_OPT)/$$name/bin/$$name; \
		rm -f $(USERFS_BIN)/$$name $(USERFS_SBIN)/$$name $(USERFS_USR_BIN)/$$name; \
		$(STRIP) --strip-all $(USERFS_OPT)/$$name/bin/$$name; \
	done

clean:
	rm -rf $(BUILD_DIR) $(TARGETS)

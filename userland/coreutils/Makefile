# Minimal userland command set

PROGRAMS = cat echo pwd true false rm touch write mkdir rmdir sleep kill ls cp mv ps stat
ARCH = arm-none-eabi-
CC = $(ARCH)gcc
LD = $(ARCH)ld

BUILD_DIR = ../../build
SRCDIR = src

LIBC_INCLUDE = $(BUILD_DIR)/include
LIBC_LIB = $(BUILD_DIR)/lib

CFLAGS = -mcpu=cortex-a15 -marm -std=gnu99 -mfpu=neon -nostdlib -nostdinc
CFLAGS += -I$(LIBC_INCLUDE) -fno-builtin -fno-stack-protector
CFLAGS += -O0 -Wall

LDFLAGS = -nostdlib -L$(LIBC_LIB)

OBJECTS = $(PROGRAMS:%=%.o)

all: $(PROGRAMS)

$(PROGRAMS): %: %.o
	@echo "Linking: $@"
	$(LD) $(LDFLAGS) -o $@ $< -lc

%.o: $(SRCDIR)/%.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	@for prog in $(PROGRAMS); do \
		cp $$prog ../../userfs/bin/$$prog; \
	done

clean:
	rm -f $(OBJECTS) $(PROGRAMS)

.PHONY: all install clean

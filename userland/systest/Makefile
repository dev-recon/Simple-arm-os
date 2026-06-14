# Configuration
PROGRAM = systest
ARCH = arm-none-eabi-
CC = $(ARCH)gcc
LD = $(ARCH)ld

# Repertoires
BUILD_DIR = ../../build
SRCDIR = src

# Paths pour libc
LIBC_INCLUDE = $(BUILD_DIR)/include
LIBC_LIB = $(BUILD_DIR)/lib

# Flags
CFLAGS = -mcpu=cortex-a15 -marm -std=gnu99 -mfpu=neon -nostdlib -nostdinc
CFLAGS += -I$(LIBC_INCLUDE) -fno-builtin -fno-stack-protector
CFLAGS += -O0 -Wall

LDFLAGS = -nostdlib -L$(LIBC_LIB)

# Fichiers
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=%.o)

# Cibles
all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	@echo "Linking: $@"
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) -lc

%.o: $(SRCDIR)/%.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) -c $< -o $@

install: $(PROGRAM)
	cp $(PROGRAM) ../../userfs/bin

clean:
	rm -f $(OBJECTS) $(PROGRAM)

.PHONY: all install clean

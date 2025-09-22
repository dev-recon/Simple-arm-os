# Configuration
PROGRAM = malloc
ARCH = arm-none-eabi-
CC = $(ARCH)gcc
LD = $(ARCH)ld

# Répertoires
BUILD_DIR = ../../build
USERLAND_DIR = ..
SRCDIR = src

# Paths pour libc
LIBC_INCLUDE = $(BUILD_DIR)/include
LIBC_LIB = $(BUILD_DIR)/lib

# Flags
CFLAGS = -mcpu=cortex-a15 -marm -std=gnu99 -mfpu=neon -nostdlib -nostdinc
CFLAGS += -I$(LIBC_INCLUDE) -fno-builtin -fno-stack-protector
CFLAGS += -O0  -Wall

LDFLAGS = -nostdlib -L$(LIBC_LIB)

# Fichiers
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=%.o)

# Cibles
all: $(PROGRAM)

# Linkage avec CRT0 commun
$(PROGRAM): $(OBJECTS)
#$(PROGRAM):  $(OBJECTS)
	@echo "Linking: $@"
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) -lc

# Compilation des sources du programme
%.o: $(SRCDIR)/%.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage
clean:
	rm -f $(OBJECTS) $(PROGRAM)

# Vérifications
check-deps:
	@if [ ! -f "$(CRT0_DIR)/crt0.S" ]; then \
		echo "ERROR: CRT0 not found at $(CRT0_DIR)/crt0.S"; exit 1; \
	fi
	@if [ ! -f "$(LIBC_LIB)/libc.a" ]; then \
		echo "ERROR: libc.a not found. Run 'make install' in libc/"; exit 1; \
	fi

.PHONY: all clean check-deps

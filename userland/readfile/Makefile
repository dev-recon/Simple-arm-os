# Configuration
PROGRAM = readfile
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

# Linkage 
$(PROGRAM): $(OBJECTS)
#$(PROGRAM):  $(OBJECTS)
	@echo "Linking: $@"
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS) -lc
#	$(LD) $(LDFLAGS) -o $@ $(CRT0_OBJ) $(OBJECTS) -lc

# Compilation des sources du programme
%.o: $(SRCDIR)/%.c
	@echo "Compiling: $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage
clean:
	rm -f $(OBJECTS) $(PROGRAM)
#	rm -f $(OBJECTS) $(CRT0_OBJ) $(PROGRAM)


# Vérifications
check-deps:
	@if [ ! -f "$(LIBC_LIB)/libc.a" ]; then \
		echo "ERROR: libc.a not found. Run 'make install' in libc/"; exit 1; \
	fi

.PHONY: all clean check-deps

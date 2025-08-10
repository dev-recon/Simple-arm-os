ARCH = arm-none-eabi-
CC = $(ARCH)gcc
AR = $(ARCH)ar
AS = $(ARCH)as

ARCH_FLAGS = -mcpu=cortex-a15 -marm

# Flags pour libc userspace
CFLAGS = $(ARCH_FLAGS) -std=gnu99 -mfpu=neon -nostdlib -nostdinc
CFLAGS += -fno-builtin -fno-stack-protector
CFLAGS += -D_FORTIFY_SOURCE=0  
CFLAGS += -I./include -Os -g

ASFLAGS = -mcpu=cortex-a15 -mfpu=neon

SRCDIR = src

# Répertoires d'installation
BUILD_DIR = ../build
INSTALL_LIB = $(BUILD_DIR)/lib
INSTALL_INCLUDE = $(BUILD_DIR)/include

# Sources C et Assembly
C_SOURCES = $(wildcard $(SRCDIR)/*.c)
ASM_SOURCES = $(wildcard $(SRCDIR)/*.S)

# Objects correspondants
C_OBJECTS = $(C_SOURCES:.c=.o)
ASM_OBJECTS = $(ASM_SOURCES:.S=.o)

# Tous les objects
OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

# Cible principale
all: libc.a

# Création de la librairie
libc.a: $(OBJECTS)
	@echo "Creating library: $@"
	$(AR) rcs $@ $(OBJECTS)

# Règles de compilation
%.o: %.c
	@echo "Compiling C: $<"
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	@echo "Compiling ASM: $<"
	$(AS) $(ASFLAGS) $< -o $@

# Installation de la libc
install: libc.a
	@echo "Installing libc..."
	@mkdir -p $(INSTALL_LIB) $(INSTALL_INCLUDE)
	@echo "Copying libc.a to $(INSTALL_LIB)/"
	@cp libc.a $(INSTALL_LIB)/
	@echo "Copying headers to $(INSTALL_INCLUDE)/"
	@cp -r include/* $(INSTALL_INCLUDE)/
	@echo "Installation complete!"
	@echo "  Library: $(INSTALL_LIB)/libc.a"
	@echo "  Headers: $(INSTALL_INCLUDE)/"

# Nettoyage
clean:
	@echo "Cleaning libc..."
	@rm -f $(OBJECTS) libc.a
	@echo "Clean complete"

# Nettoyage complet (avec installation)
distclean: clean
	@echo "Removing installed files..."
	@rm -rf $(BUILD_DIR)
	@echo "Distclean complete"

# Debug : vérifier les fichiers
debug:
	@echo "=== LIBC BUILD DEBUG ==="
	@echo "C sources: $(C_SOURCES)"
	@echo "ASM sources: $(ASM_SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Install lib: $(INSTALL_LIB)"
	@echo "Install include: $(INSTALL_INCLUDE)"

# Vérifier l'installation
check-install:
	@echo "Checking installation..."
	@if [ -f "$(INSTALL_LIB)/libc.a" ]; then \
		echo "✓ libc.a installed"; \
	else \
		echo "✗ libc.a missing"; \
	fi
	@if [ -f "$(INSTALL_INCLUDE)/stdio.h" ]; then \
		echo "✓ Headers installed"; \
	else \
		echo "✗ Headers missing"; \
	fi

.PHONY: all clean distclean install debug check-install
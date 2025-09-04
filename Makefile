# ARM32 Kernel Makefile

CROSS_COMPILE = arm-none-eabi-
CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)as
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

ARCH_FLAGS = -mcpu=cortex-a15 -marm
FPU_FLAGS = -mfpu=neon-vfpv4 -mfloat-abi=soft
# CORRECTION 2: Flags specifiques pour corriger les operations mathematiques
MATH_FLAGS = -fno-builtin-div -fno-builtin-mod

# CORRECTION 3: Flags pour forcer l'utilisation de vraies instructions ARM
ARM_MATH_FLAGS = -mno-unaligned-access

# Flags de compilation
ASFLAGS = -g -Iinclude

CFLAGS = -std=gnu99 $(ARCH_FLAGS) $(FPU_FLAGS) $(MATH_FLAGS) $(ARM_MATH_FLAGS) \
         -ffreestanding -nostdlib -nostartfiles -fno-inline \
         -Wall -Wextra -Werror -g -O0 -fno-omit-frame-pointer -Wformat -Wformat-security \
         -fno-builtin -fstack-protector -Wno-error=unused-function \
         -fno-pic -fno-pie \
         -Iinclude \
         -DARMV7A_KERNEL
# Flags du linker
LDFLAGS = -T linker.ld -nostdlib -Map=kernel.map

TASK_OBJS = kernel/task/task.o \
            kernel/task/task_switch.o \
            kernel/task/task_test.o \
			kernel/task/kernel_tasks.o \
            kernel/sync/spinlock.o

# Objets de la bibliotheque
LIB_OBJ = kernel/lib/kprintf.o kernel/lib/string.o kernel/lib/font_8x16.o kernel/lib/divmod.o kernel/lib/debug_print.o kernel/lib/math.o

# Objets du noyau
KERNEL_OBJS = \
	kernel/boot.o \
	kernel/main.o \
	kernel/internals/ls_process.o \
	kernel/memory/helpers.o \
	kernel/memory/physical.o \
	kernel/memory/virtual.o \
	kernel/memory/mmu.o \
	kernel/memory/kmalloc.o \
	kernel/memory/memory_detect.o \
	kernel/process/process.o \
	kernel/process/fork.o \
	kernel/process/exec.o \
	kernel/process/signal.o \
	kernel/fs/vfs.o \
	kernel/fs/fat32.o \
	kernel/fs/fat32_vfs.o \
	kernel/fs/userfs_loader.o \
	kernel/drivers/ata.o \
	kernel/drivers/keyboard.o \
	kernel/drivers/display.o \
	kernel/drivers/console.o \
	kernel/drivers/uart.o \
	kernel/drivers/ide.o \
	kernel/drivers/ramfs.o \
	kernel/drivers/tar_parser_ramfs.o \
	kernel/interrupt/exception.o \
	kernel/interrupt/interrupt.o \
	kernel/interrupt/gic.o \
	kernel/interrupt/timer.o \
	kernel/syscalls/syscall.o \
	kernel/syscalls/syscalls.o \
	kernel/syscalls/file.o \
	kernel/syscalls/process_syscalls.o \
	kernel/user/userspace.o

# Tous les objets
ALL_OBJS = $(KERNEL_OBJS) $(LIB_OBJ) $(TASK_OBJS)

# Configuration du disque
DISK_IMG = disk.img
DISK_SIZE_MB = 64
USERFS_DIR = userfs

# Cibles
TARGET = kernel
KERNEL_ELF = $(TARGET).elf
KERNEL_BIN = $(TARGET).bin

all: $(KERNEL_BIN) $(DISK_IMG)

# Linkage
$(KERNEL_ELF): $(ALL_OBJS) linker.ld
	$(LD) $(LDFLAGS) $(ALL_OBJS) -o $@

# Conversion en binaire
$(KERNEL_BIN): $(KERNEL_ELF)
	$(OBJCOPY) -O binary $< $@
	$(OBJDUMP) -d $(KERNEL_ELF) > kernel.dis

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(AS) $(ASFLAGS) $< -o $@

# Creation du disque avec FAT32 (version macOS)
$(DISK_IMG): $(USERFS_DIR)
	@echo "Creating disk image $(DISK_IMG) ($(DISK_SIZE_MB)MB) on macOS..."
	
	# Creer un fichier image vide
	dd if=/dev/zero of=$(DISK_IMG) bs=1m count=$(DISK_SIZE_MB) 2>/dev/null
	
	# Formater en FAT32 directement (plus simple sur macOS)
	mkfs.fat -F 32 -n "OSKERNEL" $(DISK_IMG)
	
	# Copier le contenu de userfs vers le disque
	@if [ -d $(USERFS_DIR) ]; then \
		echo "Copying $(USERFS_DIR) contents to disk..."; \
		find $(USERFS_DIR) -type d | while read dir; do \
			if [ "$$dir" != "$(USERFS_DIR)" ]; then \
				relpath=$$(echo $$dir | sed 's|$(USERFS_DIR)/||' | sed 's|$(USERFS_DIR)||'); \
				if [ -n "$$relpath" ]; then \
					echo "Creating directory: $$relpath"; \
					mmd -i $(DISK_IMG) "::$$relpath" 2>/dev/null || true; \
				fi; \
			fi; \
		done; \
		find $(USERFS_DIR) -type f | while read file; do \
			relpath=$$(echo $$file | sed 's|$(USERFS_DIR)/||' | sed 's|$(USERFS_DIR)/||'); \
			echo "Copying file: $$relpath"; \
			mcopy -i $(DISK_IMG) "$$file" "::$$relpath" 2>/dev/null || \
			mcopy -i $(DISK_IMG) "$$file" "::" 2>/dev/null || \
			echo "Warning: Could not copy $$file"; \
		done; \
	else \
		echo "Warning: $(USERFS_DIR) directory not found"; \
	fi
	
	@echo "Disk image $(DISK_IMG) created successfully"

# Creer le repertoire userfs avec des fichiers de test
$(USERFS_DIR):
	@echo "Creating $(USERFS_DIR) directory with test files..."
	mkdir -p $(USERFS_DIR)
	echo "Hello from the ARM32 OS!" > $(USERFS_DIR)/hello.txt
	echo "This is a test file for the kernel" > $(USERFS_DIR)/test.txt
	echo "ARM32 Kernel" > $(USERFS_DIR)/readme.txt
	echo "#!/bin/sh" > $(USERFS_DIR)/init.sh
	echo "echo 'System initialization...'" >> $(USERFS_DIR)/init.sh
	echo "echo 'Welcome to ARM32 OS'" >> $(USERFS_DIR)/init.sh
	chmod +x $(USERFS_DIR)/init.sh
	
	# Creer des sous-repertoires
	mkdir -p $(USERFS_DIR)/bin
	echo "echo 'Test program running'" > $(USERFS_DIR)/bin/test.sh
	chmod +x $(USERFS_DIR)/bin/test.sh
	echo "Binary placeholder" > $(USERFS_DIR)/bin/hello
	
	mkdir -p $(USERFS_DIR)/etc
	echo "# ARM32 OS Configuration" > $(USERFS_DIR)/etc/os.conf
	echo "version=1.0" >> $(USERFS_DIR)/etc/os.conf
	echo "architecture=arm32" >> $(USERFS_DIR)/etc/os.conf
	
	mkdir -p $(USERFS_DIR)/tmp
	echo "Temporary files directory" > $(USERFS_DIR)/tmp/README
	
	@echo "$(USERFS_DIR) directory created with test files"

# Generer les donnees userfs
userfs-data: userfs.bin

userfs.bin: $(wildcard userfs/**/*)
	./populate_userfs.sh
	./qemu_loader_method.sh

# Run avec userfs loader
run-userfs: $(KERNEL_BIN) userfs.bin
	qemu-system-arm -M virt -cpu cortex-a15 \
		-m 2G -smp 1 \
		-drive file=disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-device loader,file=userfs.bin,addr=0x50000000
#,virtualization=off,gic-version=2
#-device loader,file=userfs.bin,addr=0x41000000

debug-run-userfs: $(KERNEL_BIN) userfs.bin
	qemu-system-arm -M virt -cpu cortex-a15 \
		-m 2G -smp 1 \
		-drive file=disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-device loader,file=userfs.bin,addr=0x50000000 -s -S

# Version alternative plus simple (un seul niveau de fichiers)
disk-simple: $(USERFS_DIR)
	@echo "Creating simple disk image..."
	dd if=/dev/zero of=$(DISK_IMG) bs=1m count=$(DISK_SIZE_MB) 2>/dev/null
	mkfs.fat -F 32 -n "OSKERNEL" $(DISK_IMG)
	
	# Copier seulement les fichiers du niveau racine
	@find $(USERFS_DIR) -maxdepth 1 -type f | while read file; do \
		basename_file=$$(basename "$$file"); \
		echo "Copying $$basename_file..."; \
		mcopy -i $(DISK_IMG) "$$file" "::$$basename_file"; \
	done
	@echo "Simple disk created"

# Verifier le contenu du disque
check-disk: $(DISK_IMG)
	@echo "=== Disk image contents ==="
	mdir -i $(DISK_IMG) :: 2>/dev/null || echo "Could not list root directory"
	@echo ""
	@echo "=== Disk image info ==="
	file $(DISK_IMG)
	@echo ""
	@echo "=== Disk size ==="
	ls -lh $(DISK_IMG)

# Extraire le contenu du disque (pour debug)
extract-disk: $(DISK_IMG)
	@echo "Extracting disk contents to disk_contents/..."
	mkdir -p disk_contents
	mcopy -s -i $(DISK_IMG) :: disk_contents/ 2>/dev/null || \
	(echo "Trying alternative extraction..."; \
	 mdir -i $(DISK_IMG) :: | tail -n +4 | awk '{print $$1}' | while read file; do \
		if [ "$$file" != "" ] && [ "$$file" != "." ] && [ "$$file" != ".." ]; then \
			echo "Extracting $$file..."; \
			mcopy -i $(DISK_IMG) "::$$file" "disk_contents/$$file" 2>/dev/null || true; \
		fi; \
	 done)

# Creer un disque de boot avec le kernel (optionnel)
boot-disk: $(KERNEL_BIN) $(USERFS_DIR)
	@echo "Creating bootable disk with kernel..."
	dd if=/dev/zero of=boot_$(DISK_IMG) bs=1m count=$(DISK_SIZE_MB) 2>/dev/null
	mkfs.fat -F 32 -n "ARMBOOT" boot_$(DISK_IMG)
	mcopy -i boot_$(DISK_IMG) $(KERNEL_BIN) ::$(KERNEL_BIN)
	@if [ -d $(USERFS_DIR) ]; then \
		find $(USERFS_DIR) -type f | while read file; do \
			basename_file=$$(basename "$$file"); \
			mcopy -i boot_$(DISK_IMG) "$$file" "::$$basename_file"; \
		done; \
	fi
	@echo "Bootable disk created as boot_$(DISK_IMG)"

clean:
	rm -f $(ALL_OBJS) $(KERNEL_ELF) $(KERNEL_BIN)

clean-all: clean
	rm -f $(DISK_IMG) boot_$(DISK_IMG)
	rm -rf $(USERFS_DIR) disk_contents

# Essayez cette configuration alternative :
run-alt: $(KERNEL_BIN) $(DISK_IMG)
	qemu-system-arm -M vexpress-a9 -cpu cortex-a9 \
		-m 1G \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-blockdev driver=file,filename=$(DISK_IMG),node-name=disk0 \
		-device virtio-blk-device,drive=disk0,bus=virtio-mmio-bus.0

run-trace: $(KERNEL_BIN) $(DISK_IMG)
	qemu-system-arm -M vexpress-a9 -cpu cortex-a9 \
		-m 1G \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-blk-device,drive=disk0,bus=virtio-mmio-bus.0 \
		-trace "virtio*" -trace "virtqueue*" -trace "virtio_blk*" \
		-D qemu-virtio.log 

run-mmio: $(KERNEL_BIN) $(DISK_IMG)
	qemu-system-arm -M virt -cpu cortex-a15 \
		-m 1G -smp 1 \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-blk-device,drive=disk0,bus=virtio-mmio-bus.0 \
		-d int,guest_errors,unimp -D qemu.log

run: $(KERNEL_BIN) $(DISK_IMG)
	qemu-system-arm -M virt,highmem=off -cpu cortex-a15 \
		-m 1G -smp 1 \
		-kernel $(KERNEL_BIN) \
		-nographic \
		-drive file=disk.img,if=virtio,format=raw

#-machine secure=on \
#-bios bl1.bin \
#-global virtio-mmio.force-legacy=true

debug: $(KERNEL_BIN) $(DISK_IMG)
	qemu-system-arm -machine virt -cpu cortex-a15 -m 128M \
		-kernel $(KERNEL_BIN) -nographic -s -S \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-blk-device,drive=disk0
#,bus=virtio-mmio-bus.0

# Commandes d'aide
help:
	@echo "Available targets:"
	@echo "  all          - Build kernel and create disk"
	@echo "  $(KERNEL_BIN)   - Build kernel only"
	@echo "  $(DISK_IMG)       - Create disk with userfs content"
	@echo "  disk-simple  - Create simple disk (files only)"
	@echo "  check-disk   - Display disk contents and info"
	@echo "  extract-disk - Extract disk contents for inspection"
	@echo "  boot-disk    - Create bootable disk with kernel"
	@echo "  run          - Run kernel in QEMU"
	@echo "  debug        - Run kernel in QEMU with debugging"
	@echo "  clean        - Remove object files and binaries"
	@echo "  clean-all    - Remove everything including disk"
	@echo "  help         - Show this help"

# Debug targets
test-kernel: $(KERNEL_BIN)
	@echo "Testing kernel without disk..."
	qemu-system-arm \
		-M vexpress-a9 -cpu cortex-a9 \
		-m 1G \
		-kernel $(KERNEL_BIN) \
		-nographic

debug-verbose: $(KERNEL_BIN)
	@echo "Running with verbose debug..."
	qemu-system-arm -machine virt -cpu cortex-a15 -m 128M \
		-kernel $(KERNEL_BIN) -nographic \
		-d cpu,int,guest_errors

debug-monitor: $(KERNEL_BIN)
	@echo "Running with QEMU monitor (type 'info registers' then 'quit')..."
	qemu-system-arm -machine virt -cpu cortex-a15 -m 128M \
		-kernel $(KERNEL_BIN) -nographic \
		-monitor stdio

debug-trace: $(KERNEL_BIN)
	@echo "Running with execution trace..."
	qemu-system-arm -machine virt -cpu cortex-a15 -m 128M \
		-kernel $(KERNEL_BIN) -nographic \
		-d exec,cpu -D qemu.log
	@echo "Check qemu.log for execution trace"

info: $(KERNEL_ELF)
	@echo "=== Kernel Info ==="
	file $(KERNEL_ELF) $(KERNEL_BIN)
	@echo ""
	@echo "=== Entry Point ==="
	$(CROSS_COMPILE)readelf -h $(KERNEL_ELF) | grep Entry
	@echo ""
	@echo "=== Sections ==="
	$(CROSS_COMPILE)readelf -S $(KERNEL_ELF) | head -20
	@echo ""
	@echo "=== First bytes of binary ==="
	hexdump -C $(KERNEL_BIN) | head -5

disasm: $(KERNEL_ELF)
	@echo "=== Disassembly of entry point ==="
	$(CROSS_COMPILE)objdump -d $(KERNEL_ELF) | head -50

symbols: $(KERNEL_ELF)
	@echo "=== Important symbols ==="
	$(CROSS_COMPILE)nm $(KERNEL_ELF) | grep -E "(_start|kernel_main|early_init|uart)"

# Test avec machine differente
test-versatile: $(KERNEL_BIN)
	@echo "Testing with versatile machine..."
	qemu-system-arm -machine versatilepb -cpu arm1176 -m 256M \
		-kernel $(KERNEL_BIN) -nographic

# Test simple d'affichage
test-simple: 
	@echo "Creating minimal test kernel..."
	@echo '.global _start' > test_simple.s
	@echo '_start:' >> test_simple.s
	@echo '  ldr r0, =0x09000000' >> test_simple.s
	@echo '  mov r1, #72' >> test_simple.s
	@echo '  str r1, [r0]' >> test_simple.s
	@echo '  mov r1, #105' >> test_simple.s
	@echo '  str r1, [r0]' >> test_simple.s
	@echo '  mov r1, #10' >> test_simple.s
	@echo '  str r1, [r0]' >> test_simple.s
	@echo 'loop: b loop' >> test_simple.s
	$(AS) $(ASFLAGS) test_simple.s -o test_simple.o
	$(LD) test_simple.o -Ttext=0x40000000 -o test_simple.elf
	$(OBJCOPY) -O binary test_simple.elf test_simple.bin
	@echo "Running simple test (should print 'Hi')..."
	qemu-system-arm -machine virt -cpu cortex-a15 -m 128M \
		-kernel test_simple.bin -nographic
	@rm -f test_simple.s test_simple.o test_simple.elf test_simple.bin

# Mise a jour de la cible .PHONY
.PHONY: all clean clean-all run debug check-disk disk-simple extract-disk boot-disk help test-kernel debug-verbose debug-monitor debug-trace info disasm symbols test-versatile test-simple
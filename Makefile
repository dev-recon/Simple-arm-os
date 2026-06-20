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
         -fno-builtin -fstack-protector -Wno-unused-function \
         -MMD -MP \
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
	kernel/fs/mount.o \
	kernel/fs/fat32.o \
	kernel/fs/fat32_vfs.o \
	kernel/fs/ext2_vfs.o \
	kernel/fs/procfs.o \
	kernel/fs/userfs_loader.o \
	kernel/drivers/ata.o \
	kernel/drivers/keyboard.o \
	kernel/drivers/display.o \
	kernel/drivers/console.o \
	kernel/drivers/virtio_gpu.o \
	kernel/drivers/uart.o \
	kernel/drivers/tty.o \
	kernel/drivers/null.o \
	kernel/drivers/power.o \
	kernel/drivers/ide.o \
	kernel/drivers/ramfs.o \
	kernel/drivers/tar_parser_ramfs.o \
	kernel/drivers/virtio_block.o \
	kernel/interrupt/exception.o \
	kernel/interrupt/interrupt.o \
	kernel/interrupt/gic.o \
	kernel/interrupt/timer.o \
	kernel/syscalls/syscall.o \
	kernel/syscalls/syscalls.o \
	kernel/syscalls/file.o \
	kernel/syscalls/shm.o \
	kernel/syscalls/process_syscalls.o \
	kernel/user/userspace.o

# Tous les objets
ALL_OBJS = $(KERNEL_OBJS) $(LIB_OBJ) $(TASK_OBJS)
DEPFILES = $(ALL_OBJS:.o=.d)

# Configuration du disque
DISK_IMG     = disk.img
FAT32_IMG    = fat32.img
EXT2_IMG     = ext2.img
FAT32_SIZE_MB = 64
EXT2_SIZE_MB = 64
DISK_SIZE_MB = $(shell echo $$(($(FAT32_SIZE_MB) + $(EXT2_SIZE_MB))))
USERFS_DIR   = userfs
USERLAND_DIR = userland
EXT2_STAGING = /tmp/ext2_staging
USERFS_FILES := $(shell find $(USERFS_DIR) -type f 2>/dev/null)
USERFS_DIRS  := $(shell find $(USERFS_DIR) -type d 2>/dev/null)
USERFS_LINKS := $(shell find $(USERFS_DIR) -type l 2>/dev/null)
USERFS_BIN_FILES := $(shell find $(USERFS_DIR)/bin -type f 2>/dev/null)
FAT32_MNT_FILES := \
	$(USERFS_DIR)/README.TXT \
	$(USERFS_DIR)/hello.txt \
	$(USERFS_DIR)/test.txt \
	$(USERFS_DIR)/home/user/profile.txt \
	$(USERFS_DIR)/tmp/README

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

# Partition FAT32 montee sous /mnt. Elle reste volontairement minimale :
# ext2 est le root complet, FAT32 sert surtout d'espace de compatibilite/echange.
$(FAT32_IMG): $(USERFS_DIR) $(FAT32_MNT_FILES)
	@echo "=== Creating FAT32 image ($(FAT32_SIZE_MB) MB) ==="
	dd if=/dev/zero of=$(FAT32_IMG) bs=1m count=$(FAT32_SIZE_MB) 2>/dev/null
	mkfs.fat -F 32 -n "OSKERNEL" $(FAT32_IMG)
	@for dir in home home/user tmp; do \
		mmd -i $(FAT32_IMG) "::$$dir" || true; \
	done
	@for file in README.TXT hello.txt test.txt home/user/profile.txt tmp/README; do \
		if [ -f "$(USERFS_DIR)/$$file" ]; then \
			mcopy -o -i $(FAT32_IMG) "$(USERFS_DIR)/$$file" "::$$file"; \
		fi; \
	done
	@echo "FAT32 image created"

# Partition ext2 (64 Mo) — peuplée avec tout userfs via mke2fs + debugfs
E2FSPROGS_PREFIX ?= $(shell \
	if command -v brew >/dev/null 2>&1; then \
		brew --prefix e2fsprogs 2>/dev/null; \
	elif [ -d /opt/homebrew/opt/e2fsprogs ]; then \
		echo /opt/homebrew/opt/e2fsprogs; \
	elif [ -d /usr/local/opt/e2fsprogs ]; then \
		echo /usr/local/opt/e2fsprogs; \
	fi)
MKE2FS  := $(E2FSPROGS_PREFIX)/sbin/mke2fs
DEBUGFS := $(E2FSPROGS_PREFIX)/sbin/debugfs

$(EXT2_IMG): $(USERFS_DIR) $(USERFS_FILES) $(USERFS_DIRS) $(USERFS_LINKS)
	@echo "=== Creating ext2 image ($(EXT2_SIZE_MB) MB) ==="
	@if [ ! -x "$(MKE2FS)" ] || [ ! -x "$(DEBUGFS)" ]; then \
		echo "Error: e2fsprogs not found — run: brew install e2fsprogs"; \
		echo "MKE2FS=$(MKE2FS)"; \
		echo "DEBUGFS=$(DEBUGFS)"; \
		exit 1; \
	fi
	dd if=/dev/zero of=$(EXT2_IMG) bs=1m count=$(EXT2_SIZE_MB) 2>/dev/null
	$(MKE2FS) -q -t ext2 -F -L OS_EXT2 $(EXT2_IMG)
	@( find $(USERFS_DIR) -type d | sort | while read dir; do \
	       if [ "$$dir" != "$(USERFS_DIR)" ]; then \
	           relpath=$$(echo "$$dir" | sed 's|$(USERFS_DIR)/||'); \
	           printf 'mkdir /%s\n' "$$relpath"; \
	           case "$$relpath" in \
	               tmp) mode=040777; uid=0; gid=0 ;; \
	               dev) mode=040755; uid=0; gid=0 ;; \
	               root|root/*) mode=040700; uid=0; gid=0 ;; \
	               home/user|home/user/*) mode=040755; uid=1000; gid=1000 ;; \
	               *) mode=040755; uid=0; gid=0 ;; \
	           esac; \
	           printf 'set_inode_field /%s mode %s\n' "$$relpath" "$$mode"; \
	           printf 'set_inode_field /%s uid %s\n' "$$relpath" "$$uid"; \
	           printf 'set_inode_field /%s gid %s\n' "$$relpath" "$$gid"; \
	       fi; \
	   done; \
	   find $(USERFS_DIR) -type f | sort | while read f; do \
	       relpath=$$(echo "$$f" | sed 's|$(USERFS_DIR)/||'); \
	       case "$$relpath" in dev/tty0|dev/console) continue ;; esac; \
	       printf 'write %s /%s\n' "$$f" "$$relpath"; \
	       case "$$relpath" in \
	           sbin/init) mode=0100700 ;; \
	           bin/su) mode=0104755 ;; \
	           bin/*|sbin/*|usr/bin/*|opt/*/bin/*|legacy/bin-libc/*|init.sh) mode=0100755 ;; \
	           home/user/copy_renamed) mode=0100755 ;; \
	           *) mode=0100644 ;; \
	       esac; \
	       case "$$relpath" in \
	           home/user/*) uid=1000; gid=1000 ;; \
	           *) uid=0; gid=0 ;; \
	       esac; \
	       printf 'set_inode_field /%s mode %s\n' "$$relpath" "$$mode"; \
	       printf 'set_inode_field /%s uid %s\n' "$$relpath" "$$uid"; \
	       printf 'set_inode_field /%s gid %s\n' "$$relpath" "$$gid"; \
	   done; \
	   find $(USERFS_DIR) -type l | sort | while read l; do \
	       relpath=$$(echo "$$l" | sed 's|$(USERFS_DIR)/||'); \
	       target=$$(readlink "$$l"); \
	       printf 'symlink /%s %s\n' "$$relpath" "$$target"; \
	   done; \
	   printf 'cd /dev\n'; \
	   printf 'mknod console c 5 1\n'; \
	   printf 'set_inode_field console mode 020666\n'; \
	   printf 'set_inode_field console uid 0\n'; \
	   printf 'set_inode_field console gid 0\n'; \
	   printf 'mknod tty0 c 4 0\n'; \
	   printf 'set_inode_field tty0 mode 020666\n'; \
	   printf 'set_inode_field tty0 uid 0\n'; \
	   printf 'set_inode_field tty0 gid 0\n'; \
	   printf 'mknod null c 1 3\n'; \
	   printf 'set_inode_field null mode 020666\n'; \
	   printf 'set_inode_field null uid 0\n'; \
	   printf 'set_inode_field null gid 0\n'; \
	   printf 'quit\n' ) | $(DEBUGFS) -w -f - $(EXT2_IMG) >/dev/null
	$(DEBUGFS) -R 'ls -l /bin' $(EXT2_IMG) >/dev/null
	@echo "ext2 image created"

# Disque final = ext2 + FAT32 concaténés
$(DISK_IMG): $(FAT32_IMG) $(EXT2_IMG)
	@echo "=== Assembling $(DISK_IMG) (ext2 + FAT32) ==="
	dd if=/dev/zero of=$(DISK_IMG) bs=1m count=$(DISK_SIZE_MB) 2>/dev/null
	dd if=$(EXT2_IMG) of=$(DISK_IMG) bs=1m seek=0 conv=notrunc 2>/dev/null
	dd if=$(FAT32_IMG) of=$(DISK_IMG) bs=1m seek=$(EXT2_SIZE_MB) conv=notrunc 2>/dev/null
	@echo "Disk image $(DISK_IMG) created ($(DISK_SIZE_MB) MB)"

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
	mkdir -p $(USERFS_DIR)/bin $(USERFS_DIR)/usr/bin
	echo "echo 'Test program running'" > $(USERFS_DIR)/bin/test.sh
	chmod +x $(USERFS_DIR)/bin/test.sh
	echo "Binary placeholder" > $(USERFS_DIR)/usr/bin/hello
	
	mkdir -p $(USERFS_DIR)/etc
	echo "# ARM32 OS Configuration" > $(USERFS_DIR)/etc/os.conf
	echo "version=1.0" >> $(USERFS_DIR)/etc/os.conf
	echo "architecture=arm32" >> $(USERFS_DIR)/etc/os.conf
	
	mkdir -p $(USERFS_DIR)/tmp
	echo "Temporary files directory" > $(USERFS_DIR)/tmp/README
	
	mkdir -p $(USERFS_DIR)/dev
	touch $(USERFS_DIR)/dev/tty0 $(USERFS_DIR)/dev/console
	
	@echo "$(USERFS_DIR) directory created with test files"

# Generer les donnees userfs
userfs-data: userfs.bin

userfs.bin: $(wildcard userfs/**/*)
	./populate_userfs.sh
	./qemu_loader_method.sh

# Run avec userfs loader
run-userfs: $(KERNEL_BIN)
	qemu-system-arm -M virt -cpu cortex-a15 \
		-m 2G -smp 1 \
		-drive file=disk.img,if=none,format=raw,id=hd0 \
		-device virtio-blk-device,drive=hd0 \
		-kernel $(KERNEL_BIN) \
		-nographic

#-device loader,file=userfs.bin,addr=0x50000000
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
	@echo "=== ext2 root contents (mounted as /) ==="
	@if [ -x "$(DEBUGFS)" ]; then \
		$(DEBUGFS) -R 'ls -l /' $(EXT2_IMG); \
	else \
		echo "Could not list ext2 root: debugfs not found"; \
	fi
	@echo ""
	@echo "=== ext2 /bin contents ==="
	@if [ -x "$(DEBUGFS)" ]; then \
		$(DEBUGFS) -R 'ls -l /bin' $(EXT2_IMG); \
	else \
		echo "Could not list ext2 /bin: debugfs not found"; \
	fi
	@echo ""
	@echo "=== FAT32 contents (mounted as /mnt) ==="
	@mdir -i $(FAT32_IMG) :: 2>/dev/null || echo "Could not list FAT32 /mnt directory"
	@echo ""
	@echo "=== Disk image info ==="
	@file $(FAT32_IMG)
	@file $(EXT2_IMG)
	@file $(DISK_IMG)
	@echo ""
	@echo "=== Disk size ==="
	@ls -lh $(FAT32_IMG) $(EXT2_IMG)
	@ls -lh $(DISK_IMG)

# Extraire le contenu du disque (pour debug)
extract-disk: $(DISK_IMG)
	@echo "Extracting ext2 / and FAT32 /mnt to disk_contents/..."
	rm -rf disk_contents
	mkdir -p disk_contents/ext2-root disk_contents/fat32-mnt
	@if [ -x "$(DEBUGFS)" ]; then \
		$(DEBUGFS) -R 'rdump / disk_contents/ext2-root' $(EXT2_IMG) >/dev/null 2>/dev/null || \
			echo "Could not extract ext2 root"; \
	else \
		echo "Could not extract ext2 root: debugfs not found"; \
	fi
	@mcopy -s -i $(FAT32_IMG) :: disk_contents/fat32-mnt/ 2>/dev/null || \
		echo "Could not extract FAT32 /mnt contents"
	@echo "Extracted to disk_contents/ext2-root and disk_contents/fat32-mnt"

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
	rm -f $(ALL_OBJS) $(DEPFILES) $(KERNEL_ELF) $(KERNEL_BIN)

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

-include $(DEPFILES)

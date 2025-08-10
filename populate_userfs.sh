#!/bin/bash
# populate_userfs.sh - Peupler le repertoire userfs avec des fichiers de test

USERFS_DIR="./userfs"

echo "=== POPULATING USERFS DIRECTORY ==="
echo "Adding test files to existing userfs structure..."

# Verifier que userfs existe
if [ ! -d "$USERFS_DIR" ]; then
    echo "Error: userfs directory not found!"
    exit 1
fi

echo "Current userfs structure:"
tree "$USERFS_DIR" 2>/dev/null || ls -la "$USERFS_DIR"

# Creer les repertoires manquants
echo ""
echo "1. Creating additional directories..."
mkdir -p "$USERFS_DIR/etc"
mkdir -p "$USERFS_DIR/tmp"
mkdir -p "$USERFS_DIR/var/log"
mkdir -p "$USERFS_DIR/home/user/documents"

# Creer les fichiers de configuration
echo "2. Creating configuration files..."

# README principal
cat > "$USERFS_DIR/README.TXT" << 'EOF'
Welcome to UserFS Test Filesystem
==================================

This is a test filesystem for kernel development.
It contains various files and directories to test VFS functionality.

Directory structure:
- /bin         : System binaries (your compiled executables)
- /usr/bin     : User binaries
- /usr/lib     : Libraries  
- /etc         : Configuration files
- /home        : User home directories
- /tmp         : Temporary files
- /var/log     : Log files

You can compile executables and place them in bin/ or usr/bin/
Test your VFS implementation with these files!
EOF

# Fichiers /etc
cat > "$USERFS_DIR/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:Test User:/home/user:/bin/sh
daemon:x:2:2:System Daemon:/sbin:/bin/false
guest:x:1001:1001:Guest User:/home/guest:/bin/sh
EOF

cat > "$USERFS_DIR/etc/hosts" << 'EOF'
127.0.0.1   localhost
127.0.1.1   testhost
127.0.0.2   kerneldev
::1         localhost ip6-localhost ip6-loopback
EOF

cat > "$USERFS_DIR/etc/config.txt" << 'EOF'
[system]
kernel_version=1.0.0
debug_level=2
heap_size=8MB
userfs_enabled=true

[filesystem]
type=userfs
base_dir=./userfs
executable_dirs=/bin,/usr/bin
library_dirs=/usr/lib

[development]
compile_target=arm-none-eabi
optimization_level=O2
debug_symbols=true
EOF

cat > "$USERFS_DIR/etc/fstab" << 'EOF'
# Filesystem table for test kernel
# <device>     <mount>    <type>   <options>
/dev/ramfs0    /          ramfs    rw,defaults
/dev/virtio0   /mnt/disk  fat32    rw,defaults
tmpfs          /tmp       tmpfs    rw,size=10M
EOF

# Fichiers utilisateur
echo "3. Creating user files..."

cat > "$USERFS_DIR/home/user/profile.txt" << 'EOF'
# User profile configuration for test kernel
export PATH=/bin:/usr/bin
export HOME=/home/user
export PS1='user@kernel:$ '
export TERM=vt100

# Welcome message
echo "Welcome to the kernel development environment!"
echo "Available commands in /bin and /usr/bin"
echo "Your files are in $HOME"

# Aliases for development
alias ll='ls -la'
alias la='ls -A'
alias grep='grep --color=auto'
EOF

cat > "$USERFS_DIR/home/user/.bashrc" << 'EOF'
# Bashrc for test environment
source ~/profile.txt

# History settings
export HISTSIZE=1000
export HISTFILESIZE=2000

# Development helpers
alias make-clean='make clean'
alias make-debug='make DEBUG=1'
alias run-tests='./run_tests.sh'

echo "Development environment loaded!"
EOF

cat > "$USERFS_DIR/home/user/documents/readme.txt" << 'EOF'
Personal Development Files
==========================

This directory contains user documents and development files.

Suggested usage:
- Store your source code here
- Keep development notes
- Test data files
- Build scripts

Available system:
- Compiler toolchain in /usr/bin
- Libraries in /usr/lib  
- System tools in /bin
- Configuration in /etc

Happy kernel development! -
EOF

cat > "$USERFS_DIR/home/user/documents/todo.txt" << 'EOF'
Kernel Development TODO
=======================

VFS Testing:
[ ] Test file creation
[ ] Test directory navigation  
[ ] Test file reading/writing
[ ] Test permission system
[ ] Test symlinks

Process Management:
[ ] Test process creation
[ ] Test process scheduling
[ ] Test IPC mechanisms
[ ] Test signal handling

Memory Management:
[ ] Test heap allocation
[ ] Test memory mapping
[ ] Test memory protection
[ ] Test swap functionality

Device Drivers:
[ ] Test keyboard input
[ ] Test display output
[ ] Test storage devices
[ ] Test network interface

System Calls:
[ ] Implement open/close/read/write
[ ] Implement fork/exec/wait
[ ] Implement memory syscalls
[ ] Implement time syscalls
EOF

# Fichiers de log systeme
echo "4. Creating system log files..."

cat > "$USERFS_DIR/var/log/kernel.log" << 'EOF'
Kernel Development Log
======================

[BOOT] Kernel initialization started
[MEMORY] Physical memory allocator ready
[MEMORY] Virtual memory system enabled
[MEMORY] Kernel heap initialized (8MB)
[FILESYSTEM] RAMFS mounted successfully
[FILESYSTEM] UserFS directory structure loaded
[VFS] Virtual filesystem layer initialized
[PROCESS] Process management system ready
[INTERRUPT] Interrupt handlers configured
[TIMER] System timer operational
[FILESYSTEM] Root filesystem ready for testing

[STATUS] Kernel ready for development and testing!
EOF

cat > "$USERFS_DIR/var/log/system.log" << 'EOF'
System Events Log
=================

[INIT] System startup sequence initiated
[HARDWARE] ARM Cortex-A15 processor detected
[MEMORY] 1GB RAM available
[STORAGE] RAMFS filesystem created (64MB)
[NETWORK] Virtual network interface ready
[USER] Default user environment configured
[DEBUG] Debug logging enabled
[TEST] Test filesystem populated
[READY] System ready for user programs

Next: Compile and test user programs!
EOF

# Scripts d'aide pour le developpement
echo "5. Creating development helper scripts..."

cat > "$USERFS_DIR/usr/bin/hello" << 'EOF'
#!/bin/sh
# Simple hello world script for testing
echo "Hello from UserFS!"
echo "This script is running in your kernel environment."
echo "Current directory: $(pwd)"
echo "Available files:"
ls -la
EOF

chmod +x "$USERFS_DIR/usr/bin/hello"

cat > "$USERFS_DIR/usr/bin/test-vfs" << 'EOF'
#!/bin/sh
# VFS testing script
echo "=== VFS Testing Script ==="
echo "Testing basic filesystem operations..."

echo "1. Current directory:"
pwd

echo "2. Directory listing:"
ls -la

echo "3. File reading test:"
if [ -f "/etc/passwd" ]; then
    echo "Reading /etc/passwd:"
    cat /etc/passwd
else
    echo "Could not find /etc/passwd"
fi

echo "4. Write test:"
echo "Test data from VFS script" > /tmp/test.txt
if [ -f "/tmp/test.txt" ]; then
    echo "Write successful, content:"
    cat /tmp/test.txt
else
    echo "Write test failed"
fi

echo "=== VFS Test Complete ==="
EOF

chmod +x "$USERFS_DIR/usr/bin/test-vfs"

# Makefile pour compiler des programmes dans userfs
cat > "$USERFS_DIR/Makefile" << 'EOF'
# Makefile for UserFS programs
CC = arm-none-eabi-gcc
CFLAGS = -march=armv7-a -mtune=cortex-a15 -marm -O2 -Wall -Wextra
LDFLAGS = -static -nostdlib

# Source directories
SRCDIR = src
BINDIR = bin
USRBINDIR = usr/bin

# Default target
all: hello test-prog

# Simple hello world program
hello: $(SRCDIR)/hello.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ $<

# Test program for VFS
test-prog: $(SRCDIR)/test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(USRBINDIR)/$@ $<

# Create source directory and example files
setup:
	mkdir -p $(SRCDIR)
	echo '#include <syscalls.h>' > $(SRCDIR)/hello.c
	echo 'int main() { write(1, "Hello from UserFS!\\n", 20); return 0; }' >> $(SRCDIR)/hello.c

clean:
	rm -f $(BINDIR)/* $(USRBINDIR)/test-prog

.PHONY: all setup clean
EOF

# Structure finale
echo ""
echo "6. Final userfs structure:"
tree "$USERFS_DIR" 2>/dev/null || find "$USERFS_DIR" -type f | sort

echo ""
echo "=== USERFS POPULATED SUCCESSFULLY! ==="
echo ""
echo "Your userfs now contains:"
echo "- System directories: /etc, /tmp, /var/log"  
echo "- User directories: /home/user with real files"
echo "- Configuration files in /etc"
echo "- User files and development docs"
echo "- System logs in /var/log"
echo "FIX Helper scripts in /usr/bin"
echo "📋 Makefile for compiling your programs"
echo ""
echo "Next steps:"
echo "1. Compile your executables and place them in bin/ or usr/bin/"
echo "2. Create RAMFS image: ./create_userfs_image.sh"
echo "3. Test with your kernel!"
echo ""
echo "To create a filesystem image from this:"
echo "  ./create_userfs_image.sh"
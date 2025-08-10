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

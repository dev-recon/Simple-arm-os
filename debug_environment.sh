#!/bin/bash

echo "=== TOOLCHAIN INFO ==="
arm-none-eabi-gcc --version | head -1
arm-none-eabi-ld --version | head -1
arm-none-eabi-objcopy --version | head -1

echo -e "\n=== COMPILATION FLAGS ==="
echo "Current CFLAGS: -march=armv7-a -std=gnu89 -ffreestanding -nostdlib -nostartfiles -Wall -Wextra -O2 -g -Iinclude -fno-builtin -fno-stack-protector"

echo -e "\n=== SECTIONS ANALYSIS ==="
arm-none-eabi-readelf -S kernel.elf | grep -E "(Num|text|rodata|data|bss)"

echo -e "\n=== SEGMENTS ANALYSIS ==="
arm-none-eabi-readelf -l kernel.elf

echo -e "\n=== SYMBOL TABLE ==="
arm-none-eabi-nm kernel.elf | grep -E "(test_string|uart_puts|main)"

echo -e "\n=== DISASSEMBLY OF PROBLEM FUNCTION ==="
arm-none-eabi-objdump -d kernel.elf | grep -A 20 "uart_puts"

echo -e "\n=== STRING LITERALS CONTENT ==="
arm-none-eabi-objdump -s -j .rodata kernel.elf | head -20

echo -e "\n=== BINARY VS ELF SIZE ==="
ls -la kernel.elf kernel.bin

echo -e "\n=== MEMORY LAYOUT ==="
arm-none-eabi-readelf -S kernel.elf | awk 'NR>5 && /PROGBITS|NOBITS/ {printf "%-15s 0x%s size:0x%s\n", $2, $4, $6}'

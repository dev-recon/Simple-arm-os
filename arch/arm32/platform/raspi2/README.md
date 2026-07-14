# Raspberry Pi ARM32 Shared Backend

This directory contains the low-level ARM32 Raspberry Pi device backend shared
by two deliberately separate build profiles:

- `TARGET_PLATFORM=raspi2`: QEMU `raspi2b`, Cortex-A7;
- `TARGET_PLATFORM=raspi3`: Raspberry Pi 3 hardware, Cortex-A53 in AArch32.

The target distinction matters. QEMU and hardware expose different timer,
firmware handoff, poweroff, and SMP behavior even when they share BCM283x MMIO
blocks. Keep platform quirks selected by the build target instead of inferring
them from a generic `raspi2` directory name.

Implemented shared facilities:

- PL011 UART console on `tty0`;
- BCM2836 local interrupt controller and SGIs;
- ARM generic timer setup;
- secondary CPU release and scheduler participation;
- SD/eMMC block device;
- MBR, FAT32, and ext2 root discovery;
- Raspberry Pi firmware powerdown/halt path.

The PI3 target-specific build contract lives in:

- `arch/arm32/platform/raspi3/platform.mk`;
- `arch/arm32/include/asm/platform/raspi3.h`;
- `docs/RASPBERRY_PI3.md`.

Graphics, USB input, and networking are not part of the current Raspberry Pi
hardware milestone. UART must remain usable when adding any of those drivers.

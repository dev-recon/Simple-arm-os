# Raspberry Pi ARM32 Shared Backend

This directory contains the low-level ARM32 Raspberry Pi device backend shared
by the supported Raspberry Pi 2 hardware target and related compatibility
profiles:

- `TARGET_PLATFORM=raspi2`: Raspberry Pi 2 Model B v1.1 and QEMU `raspi2b`,
  Cortex-A7;
- `TARGET_PLATFORM=raspi3`: Raspberry Pi 3 hardware, Cortex-A53 in AArch32.

The QEMU launcher and Raspberry Pi firmware/SD staging remain separate even
when they consume the same `arm32/raspi2` kernel image. Hardware-only behavior
must stay in the Raspberry Pi platform boundary instead of leaking into the
common kernel.

Implemented shared facilities:

- PL011 UART console on `tty0`;
- BCM2836 local interrupt controller and SGIs;
- ARM generic timer setup;
- secondary CPU release and scheduler participation;
- SD/eMMC block device;
- MBR, FAT32, and ext2 root discovery;
- Raspberry Pi firmware powerdown/halt path.

The hardware build contracts live in:

- `docs/RASPBERRY_PI2.md`;
- `arch/arm32/platform/raspi3/platform.mk`;
- `arch/arm32/include/asm/platform/raspi3.h`;
- `docs/RASPBERRY_PI3.md`.

Graphics, USB input, and networking are not part of the current Raspberry Pi
hardware milestone. UART must remain usable when adding any of those drivers.
